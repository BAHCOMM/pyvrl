mod program;
mod value;

use pyo3::prelude::*;

use pyo3::{
    exceptions::PyValueError,
    PyErr,
};
use std::collections::BTreeMap;
use vrl::{
    compiler::{runtime::Runtime, TargetValue, TimeZone, Program},
    value::{Secrets, Value},
};

use value::VrlValue;

#[pyclass]
#[derive(Clone)]
struct Transform {
    #[pyo3(get)]
    pub source: String,
    program: Program,
}

#[pymethods]
impl Transform {

    #[new]
    fn __new__(source: String) -> PyResult<Self> {
        let program = program::compile_checked(&source)
            .map_err(PyErr::new::<PyValueError, _>)?;
        Ok(Self { source, program })
    }

    fn remap(&mut self, py: Python<'_>, data: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let input = data.extract::<VrlValue>()?.inner;

        // Everything that might recurse over a deep value runs on this stack,
        // including dropping it. Nothing in here may call into Python.
        let stack = value::stack_for_event(&input)?;
        let output = stacker::maybe_grow(stack, stack, || self.run(input))?;

        VrlValue::new(output).into_py_object(py)
    }
}

impl Transform {
    fn run(&self, input: Value) -> PyResult<Value> {
        let mut target = TargetValue {
            value: input,
            metadata: Value::Object(BTreeMap::new()),
            secrets: Secrets::default(),
        };

        let timezone = TimeZone::default();
        let mut runtime = Runtime::default();

        // Go through Runtime rather than Program::resolve: `return` surfaces
        // as an error from the latter, and Runtime turns it back into a value.
        let output = runtime.resolve(&mut target, &self.program, &timezone)
                            .map_err(|e| {
                                PyErr::new::<PyValueError, _>(
                                    format!("remap failure: {}", e))})?;

        value::check_output_depth(output)
    }
}

#[pymodule]
fn pyvrl(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Transform>()?;
    Ok(())
}
