use actix_web::{HttpRequest, HttpResponse};
use chrono::{Utc, Duration};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};

const SECRET_KEY: &str = "ban_cookie_secret_123";

#[derive(Serialize)]
pub struct ApiResponse {
    pub message: String,
    pub token: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

pub async fn decode_token(req: &HttpRequest) -> Result<Claims, HttpResponse> {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .replace("Bearer ", "");

    if token.is_empty() {
        return Err(HttpResponse::Unauthorized().json(ApiResponse {
            message: "No se proporcionó token".into(),
            token: None,
        }));
    }

    match decode::<Claims>(
        &token,
        &DecodingKey::from_secret(SECRET_KEY.as_ref()),
        &Validation::new(Algorithm::HS256),
    ) {
        Ok(data) => Ok(data.claims),
        Err(_) => Err(HttpResponse::Unauthorized().json(ApiResponse {
            message: "Token inválido o expirado".into(),
            token: None,
        })),
    }
}
