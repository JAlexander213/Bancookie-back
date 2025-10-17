use std::fmt::format;
use crate::models::{LoginRequest, RegisterData};
pub trait ApiActions{
    fn view_request(&self) -> String;
    fn sucess(&self) -> String;
    fn fail(&self, err: String)-> String;
}

impl ApiActions for LoginRequest{
    fn view_request(&self) -> String {
        format!("Email: {}, contraseña: {}", self.email, self.password)
    }
    fn sucess(&self) -> String {
        format!("Login de {} exitoso", self.email)
    }
    fn fail(&self, err: String)-> String{
        format!("Error: {} de {}", err, self.email)
    }
}

impl ApiActions for RegisterData{
    fn view_request(&self) -> String {
        format!("Email: {}, Usuario:{}, contraseña: {}, tipo cuenta: {}", self.email, self.usuario, self.password, self.tipo_cuenta)
    }
    fn sucess(&self) -> String {
        format!("Se registro el email: {} ", self.email)
    }
    fn fail(&self, err: String)-> String{
        format!("Error: {} de {}", err, self.email)
    }
}
