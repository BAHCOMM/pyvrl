use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::exceptions::{PyRecursionError, PyTypeError, PyValueError};
use pyo3::IntoPyObjectExt;
use std::collections::BTreeMap;
use vrl::value::Value;

use vrl::prelude::*;

/// Deepest nesting accepted in either direction. Conversion is recursive, so
/// without a limit cyclic or very deep values overflow the stack and kill the
/// interpreter. Matches serde_json's limit, and VRL's cap on `parse_json`.
const MAX_DEPTH: usize = 128;

/// Largest event accepted, by `Measured::weight`. The stack we reserve grows
/// with the event, so this bounds that reservation.
#[cfg(target_pointer_width = "64")]
const MAX_EVENT_WEIGHT: usize = 4 * 1024 * 1024;
#[cfg(not(target_pointer_width = "64"))]
const MAX_EVENT_WEIGHT: usize = 256 * 1024;

/// Stack reserved for any event: running a program at the nesting limit.
const BASE_STACK: usize = 256 * 1024;

/// Stack reserved per unit of event weight. VRL functions such as `unflatten`,
/// `parse_xml` and `set` build values as deep as their input, and those values
/// are walked and dropped recursively, so depth scales with event size. The
/// worst case measured is about 470 bytes (`compact` over `unflatten`); this
/// doubles that. Unoptimized builds have much larger stack frames.
const STACK_PER_WEIGHT: usize = if cfg!(debug_assertions) { 8192 } else { 1024 };

fn too_deep() -> PyErr {
    PyRecursionError::new_err(format!("value is nested more than {MAX_DEPTH} levels deep"))
}

struct Measured {
    /// Containers nested inside each other at the deepest point.
    depth: usize,
    /// Approximate size: every value, plus the bytes of strings and keys.
    weight: usize,
}

/// Measures a value of any depth. Uses a heap work list, not recursion, so this
/// is safe on values too deep to walk normally.
fn measure(value: &Value) -> Measured {
    let mut measured = Measured { depth: 0, weight: 0 };
    let mut pending = vec![(value, 0)];
    while let Some((value, depth)) = pending.pop() {
        measured.weight += 1;
        match value {
            Value::Array(arr) => {
                measured.depth = measured.depth.max(depth + 1);
                pending.extend(arr.iter().map(|item| (item, depth + 1)));
            },
            Value::Object(map) => {
                measured.depth = measured.depth.max(depth + 1);
                for (key, item) in map {
                    measured.weight += key.len();
                    pending.push((item, depth + 1));
                }
            },
            Value::Bytes(b) => measured.weight += b.len(),
            Value::String(s) => measured.weight += s.len(),
            Value::Regex(_) | Value::Integer(_) | Value::Float(_) | Value::Boolean(_)
            | Value::Timestamp(_) | Value::Null => {},
        }
    }
    measured
}

/// Stack to reserve while running a program over `input`.
pub fn stack_for_event(input: &Value) -> PyResult<usize> {
    let weight = measure(input).weight;
    if weight > MAX_EVENT_WEIGHT {
        return Err(PyValueError::new_err(format!(
            "event is too large: {weight} bytes, the limit is {MAX_EVENT_WEIGHT}"
        )));
    }
    Ok(BASE_STACK + weight * STACK_PER_WEIGHT)
}

/// Rejects a program's output if it is too deep to convert to Python. Must run
/// on the reserved stack, because the rejected value is dropped recursively.
pub fn check_output_depth(value: Value) -> PyResult<Value> {
    if measure(&value).depth > MAX_DEPTH {
        return Err(too_deep());
    }
    Ok(value)
}

#[pyclass]
pub struct VrlValue {
    pub inner: Value,
}

impl VrlValue {
    pub fn new(value: Value) -> Self {
        VrlValue { inner: value }
    }

    pub fn into_py_object(self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        value_to_py(self.inner, py)
    }
}

/// Callers must pass values that have been through `check_output_depth`.
fn value_to_py(value: Value, py: Python<'_>) -> PyResult<Py<PyAny>> {
    match value {
        Value::Array(arr) => {
            let list = PyList::empty(py);
            for val in arr {
                list.append(value_to_py(val, py)?)?;
            }
            list.into_py_any(py)
        },
        Value::Bytes(b) => String::from_utf8_lossy(&b).into_py_any(py),
        Value::String(s) => (&*s).into_py_any(py),
        Value::Boolean(b) => b.into_py_any(py),
        Value::Float(f) => f.into_inner().into_py_any(py),
        Value::Integer(i) => i.into_py_any(py),
        Value::Null => Ok(py.None()),
        Value::Object(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                dict.set_item(k.as_str(), value_to_py(v, py)?)?;
            }
            dict.into_py_any(py)
        },
        Value::Timestamp(ts) => ts.into_py_any(py),
        // Keep this match exhaustive: a catch-all here silently turns any
        // variant added by a vrl upgrade into None.
        Value::Regex(_) => Ok(py.None()),
    }
}

impl<'a, 'py> FromPyObject<'a, 'py> for VrlValue {
    type Error = PyErr;

    fn extract(ob: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        Ok(VrlValue::new(value_from_py(&ob, 0)?))
    }
}

fn value_from_py(ob: &Bound<'_, PyAny>, depth: usize) -> PyResult<Value> {
    let type_name = ob.get_type().name()?;
    let val: Value = match type_name.to_str()? {
        "bool" => Value::Boolean(ob.extract::<bool>()?),
        "bytes" => Value::Bytes(ob.extract::<Vec<u8>>()?.into()),
        "dict" => {
            if depth >= MAX_DEPTH {
                return Err(too_deep());
            }
            let dict = ob.cast::<PyDict>()?;
            let mut map = BTreeMap::new();
            for (k, v) in dict.iter() {
                let key: String = k.extract()?;
                map.insert(key.into(), value_from_py(&v, depth + 1)?);
            }
            Value::Object(map)
        },
        "float" => Value::Float(NotNan::new(ob.extract::<f64>()?)
                                        .map_err(|_|
                                            PyErr::new::<PyValueError, _>(
                                                "Provided float value is NaN"))?),
        "int" => Value::Integer(ob.extract::<i64>()?),
        "list" => {
            if depth >= MAX_DEPTH {
                return Err(too_deep());
            }
            let list = ob.cast::<PyList>()?;
            let mut vec = Vec::new();
            for item in list.iter() {
                vec.push(value_from_py(&item, depth + 1)?);
            }
            Value::Array(vec)
        },
        "NoneType" => Value::Null,
        "str" => Value::from(ob.extract::<String>()?),
        _ => return Err(PyTypeError::new_err("Unsupported type"))
    };

    Ok(val)
}
