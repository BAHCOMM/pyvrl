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

fn check_depth(depth: usize) -> PyResult<()> {
    if depth >= MAX_DEPTH {
        return Err(PyRecursionError::new_err(format!(
            "value is nested more than {MAX_DEPTH} levels deep"
        )));
    }
    Ok(())
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
        value_to_py(self.inner, py, 0)
    }
}

fn value_to_py(value: Value, py: Python<'_>, depth: usize) -> PyResult<Py<PyAny>> {
    match value {
        Value::Array(arr) => {
            check_depth(depth)?;
            let list = PyList::empty(py);
            for val in arr {
                list.append(value_to_py(val, py, depth + 1)?)?;
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
            check_depth(depth)?;
            let dict = PyDict::new(py);
            for (k, v) in map {
                dict.set_item(k.as_str(), value_to_py(v, py, depth + 1)?)?;
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
            check_depth(depth)?;
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
            check_depth(depth)?;
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
