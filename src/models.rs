use serde::{Deserialize, Serialize};
use sqlx::types::BigDecimal;



#[derive(Deserialize)]
pub struct RegisterData {
    pub email: String,
    pub usuario: String,
    pub password: String,
    pub tipo_cuenta: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct UserData {
    pub id: i32,
    pub email: String,
    pub usuario: String,
    pub avatar_url: String,
    pub num_cuenta: String,
    pub tipo_cuenta: String,
    pub saldo: Option<String>,
}

#[derive(Deserialize)]
pub struct DespositData{
    pub password: String,
    pub monto: f64,
}

#[derive(Deserialize)]
pub struct TransferData{
    pub cuenta_destino: String,
    pub monto: f64,
    pub password: String,
}

#[derive(Serialize)]
pub struct Movimiento {
    pub id: i32,
    pub tipo: String,
    pub monto: String,
    pub descripcion: String,
    pub fecha: String,
}