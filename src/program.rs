//! Compiles VRL source without letting deep nesting overflow the stack.
//!
//! vrl has no nesting limit, and its compiler, `resolve` and `Drop` are all
//! recursive, so a deep program segfaults the interpreter. `parse` is not
//! recursive, so we parse first and reject anything too deep before the
//! recursive stages ever see it.

use std::{panic, thread};

use vrl::{
    compiler::{compile, Program},
    diagnostic::Formatter,
    parser::{
        self,
        ast::{Assignment, AssignmentTarget, Container, Expr, FunctionCall, Node, Predicate, Query,
              QueryTarget, RootExpr, Unary},
    },
};

/// Deepest nesting accepted in a program, counting both expressions and path
/// segments, since assigning to `.a.a.a` builds a value that deep at runtime.
/// Programs within this limit are safe to run and drop on small thread stacks,
/// not only to compile.
pub const MAX_PROGRAM_DEPTH: usize = 128;

/// Base stack for the compile thread: comfortably covers compiling a program
/// at `MAX_PROGRAM_DEPTH`. Reserved lazily, so it costs address space, not RAM.
const COMPILE_STACK: usize = 64 * 1024 * 1024;

/// Extra stack per source byte. A failed parse drops its partial tree inside
/// vrl, recursively, where we can't measure it first. Depth can't exceed the
/// source length, so scaling by length keeps that drop on the stack.
const STACK_PER_SOURCE_BYTE: usize = 1024;

/// Compiles `source`, returning a printable error if it is invalid or too deep.
pub fn compile_checked(source: &str) -> Result<Program, String> {
    let stack_size = source
        .len()
        .saturating_mul(STACK_PER_SOURCE_BYTE)
        .saturating_add(COMPILE_STACK);

    thread::scope(|scope| {
        thread::Builder::new()
            .stack_size(stack_size)
            .spawn_scoped(scope, || compile_on_this_thread(source))
            .map_err(|e| format!("unable to compile program: {e}"))?
            .join()
            .unwrap_or_else(|payload| panic::resume_unwind(payload))
    })
}

fn compile_on_this_thread(source: &str) -> Result<Program, String> {
    // A parse failure falls through so compile() reports it as a diagnostic.
    if let Ok(ast) = parser::parse(source) {
        let depth = consume_and_measure(ast);
        if depth > MAX_PROGRAM_DEPTH {
            return Err(format!(
                "program is nested {depth} levels deep, the limit is {MAX_PROGRAM_DEPTH}"
            ));
        }
    }

    let fns = vrl::stdlib::all();
    compile(source, &fns)
        .map(|result| result.program)
        .map_err(|diagnostics| Formatter::new(source, diagnostics).to_string())
}

/// Returns the program's nesting depth. Takes the tree apart as it goes, using
/// a heap work list, because even dropping a deep tree normally would recurse.
fn consume_and_measure(program: parser::ast::Program) -> usize {
    let mut pending: Vec<(Node<Expr>, usize)> = Vec::new();
    for root in program {
        if let RootExpr::Expr(expr) = root.into_inner() {
            pending.push((expr, 1));
        }
    }

    let mut deepest = 0;
    let mut found = Found::default();
    while let Some((expr, depth)) = pending.pop() {
        deepest = deepest.max(depth);
        take_children(expr.into_inner(), &mut found);
        pending.extend(found.children.drain(..).map(|child| (child, depth + 1)));
    }
    deepest.max(found.longest_path)
}

#[derive(Default)]
struct Found {
    children: Vec<Node<Expr>>,
    longest_path: usize,
}

impl Found {
    fn note_path(&mut self, segments: usize) {
        self.longest_path = self.longest_path.max(segments);
    }
}

// Keep these matches exhaustive: a catch-all would let a new expression type
// added by a vrl upgrade skip the depth check and drop recursively.
fn take_children(expr: Expr, out: &mut Found) {
    match expr {
        Expr::Literal(_) | Expr::Variable(_) | Expr::Break(_) => {},
        Expr::Container(container) => take_container(container.into_inner(), out),
        Expr::IfStatement(statement) => {
            let statement = statement.into_inner();
            match statement.predicate.into_inner() {
                Predicate::One(expr) => out.children.push(*expr),
                Predicate::Many(exprs) => out.children.extend(exprs),
            }
            out.children.extend(statement.if_node.into_inner());
            if let Some(block) = statement.else_node {
                out.children.extend(block.into_inner());
            }
        },
        Expr::Op(op) => {
            let op = op.into_inner();
            out.children.push(*op.0);
            out.children.push(*op.2);
        },
        Expr::Assignment(assignment) => match assignment.into_inner() {
            Assignment::Single { target, expr, .. } => {
                take_target(target.into_inner(), out);
                out.children.push(*expr);
            },
            Assignment::Infallible { ok, err, expr, .. } => {
                take_target(ok.into_inner(), out);
                take_target(err.into_inner(), out);
                out.children.push(*expr);
            },
        },
        Expr::Query(query) => take_query(query.into_inner(), out),
        Expr::FunctionCall(call) => take_call(call.into_inner(), out),
        Expr::Unary(unary) => match unary.into_inner() {
            Unary::Not(not) => out.children.push(*not.into_inner().take().1),
        },
        Expr::Abort(abort) => out.children.extend(abort.into_inner().message.map(|message| *message)),
        Expr::Return(ret) => out.children.push(*ret.into_inner().expr),
    }
}

fn take_container(container: Container, out: &mut Found) {
    match container {
        Container::Group(group) => out.children.push(group.into_inner().into_inner()),
        Container::Block(block) => out.children.extend(block.into_inner()),
        Container::Array(array) => out.children.extend(array.into_inner()),
        Container::Object(object) => {
            out.children.extend(object.into_inner().into_iter().map(|(_, value)| value));
        },
    }
}

fn take_target(target: AssignmentTarget, out: &mut Found) {
    match target {
        AssignmentTarget::Noop => {},
        AssignmentTarget::Query(query) => take_query(query, out),
        AssignmentTarget::Internal(_, path) => {
            out.note_path(path.as_ref().map_or(0, |path| path.segments.len()));
        },
        AssignmentTarget::External(path) => {
            out.note_path(path.as_ref().map_or(0, |path| path.path.segments.len()));
        },
    }
}

fn take_query(query: Query, out: &mut Found) {
    out.note_path(query.path.segments.len());
    match query.target.into_inner() {
        QueryTarget::Internal(_) | QueryTarget::External(_) => {},
        QueryTarget::FunctionCall(call) => take_call(call, out),
        QueryTarget::Container(container) => take_container(container, out),
    }
}

fn take_call(call: FunctionCall, out: &mut Found) {
    out.children.extend(call.arguments.into_iter().map(|argument| argument.into_inner().expr));
    if let Some(closure) = call.closure {
        out.children.extend(closure.into_inner().block.into_inner());
    }
}
