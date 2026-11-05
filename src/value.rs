use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::IntoPyObjectExt;
use std::collections::BTreeMap;
use vrl::value::Value;

use vrl::prelude::*;

#[pyclass]
pub struct VrlValue {
    pub inner: Value,
}

impl VrlValue {
    pub fn new(value: Value) -> Self {
        VrlValue { inner: value }
    }

    pub fn into_py_object(self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match self.inner {
            Value::Array(arr) => {
                let list = PyList::empty(py);
                for val in arr {
                    let py_val = VrlValue { inner: val };
                    list.append(py_val.into_py_object(py)?)?;
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
                    let py_vrl_value = VrlValue { inner: v };
                    dict.set_item(k.as_str(), py_vrl_value.into_py_object(py)?)?;
                }
                dict.into_py_any(py)
            },
            Value::Timestamp(ts) => ts.into_py_any(py),
            // Keep this match exhaustive: a catch-all here silently turns any
            // variant added by a vrl upgrade into None.
            Value::Regex(_) => Ok(py.None()),
        }
    }
}

impl<'a, 'py> FromPyObject<'a, 'py> for VrlValue {
    type Error = PyErr;

    fn extract(ob: Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {

        let type_name = ob.get_type().name()?;
        let val: Value = match type_name.to_str()? {
            "bool" => Value::Boolean(ob.extract::<bool>()?),
            "bytes" => Value::Bytes(ob.extract::<Vec<u8>>()?.into()),
            "dict" => {
                let dict = ob.cast::<PyDict>()?;
                let mut map = BTreeMap::new();
                for (k, v) in dict.iter() {
                    let key: String = k.extract()?;
                    let value: VrlValue = v.extract()?;
                    map.insert(key.into(), value.inner);
                }
                Value::Object(map)
            },
            "float" => Value::Float(NotNan::new(ob.extract::<f64>()?)
                                            .map_err(|_|
                                                PyErr::new::<PyValueError, _>(
                                                    "Provided float value is NaN"))?),
            "int" => Value::Integer(ob.extract::<i64>()?),
            "list" => {
                let list = ob.cast::<PyList>()?;
                let mut vec = Vec::new();
                for item in list.iter() {
                    let value: VrlValue = item.extract()?;
                    vec.push(value.inner);
                }
                Value::Array(vec)
            },
            "NoneType" => Value::Null,
            "str" => Value::from(ob.extract::<String>()?),
            _ => return Err(PyTypeError::new_err("Unsupported type"))
        };

        Ok(VrlValue::new(val))
    }
}
