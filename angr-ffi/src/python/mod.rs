//! Python FFI using PyO3

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pyclass]
struct PyProject {
    // TODO: Wrap Project
}

#[cfg(feature = "python")]
#[pymethods]
impl PyProject {
    #[staticmethod]
    fn load(path: String) -> PyResult<Self> {
        unsafe {
            // TODO: Load project
            Ok(PyProject {})
        }
    }
}

#[cfg(feature = "python")]
#[pymodule]
fn angr_rs(_py: Python, m: &PyModule) -> PyResult<()> {
    unsafe {
        m.add_class::<PyProject>()?;
        Ok(())
    }
}
