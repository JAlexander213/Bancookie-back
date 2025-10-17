use actix_web::{web, HttpResponse, Responder, HttpRequest};
use bcrypt::{hash, verify as bcrypt_verify};
use serde::{Deserialize, Serialize};
use sqlx::{MySql, Pool};
use jsonwebtoken::{encode, decode, Header, EncodingKey, DecodingKey, Validation, Algorithm};
use chrono::{Utc, Duration};
use rand::{thread_rng, Rng};
use rand::distr::Uniform;
use rand::distr::Alphanumeric;
use sqlx::types::BigDecimal;
use std::str::FromStr;
use sqlx::Row;
use crate::models::{RegisterData, LoginRequest, UserData, DespositData, TransferData, Movimiento};
use crate::interfaces::{ApiActions};
use crate::lib::decode_token;

#[derive(Serialize)]
pub struct ApiResponse {
    message: String,
    token: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

const SECRET_KEY: &str = "ban_cookie_secret_123";


pub async fn register(
    data: web::Json<RegisterData>,
    pool: web::Data<Pool<MySql>>,
) -> impl Responder {
    // Hashear contraseña
    let hashed = match hash(&data.password, 12) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().json(ApiResponse {
            message: "Error al procesar la contraseña".into(),
            token: None,
        }),
    };

    let password= data.password.trim();

    if password.is_empty(){
        println!("{}", data.fail("La contraseña esta vacia".to_string()));
        return HttpResponse::BadRequest().json(ApiResponse{
            message: "La contraseña no puede venir vacia".to_string(),
            token: None,
        });
    }

    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().json(ApiResponse {
            message: "Error iniciando transacción".into(),
            token: None,
        }),
    };

    // Generar avatar aleatorio estilo thumbs
    let seed: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(10)
        .map(char::from)
        .collect();

    let avatar_url = format!(
        "https://api.dicebear.com/9.x/thumbs/svg?seed={}&radius=50",
        seed
    );
    

    // Insertar usuario con avatar
    if let Err(_) = sqlx::query!(
        "INSERT INTO usuarios (email, usuario, password, avatar_url) VALUES (?, ?, ?, ?)",
        data.email,
        data.usuario,
        hashed,
        avatar_url,
    )
        .execute(&mut *tx)
        .await
    {
        return HttpResponse::BadRequest().json(ApiResponse {
            message: "El correo ya está registrado o error en datos".into(),
            token: None,
        });
    }

    // Obtener ID del usuario recién creado
    let user_id = match sqlx::query_scalar!("SELECT id FROM usuarios WHERE email = ?", data.email)
        .fetch_one(&mut *tx)
        .await
    {
        Ok(id) => id,
        Err(_) => {
            tx.rollback().await.ok();
            return HttpResponse::InternalServerError().json(ApiResponse {
                message: "No se pudo obtener ID de usuario".into(),
                token: None,
            });
        }
    };

    // Generar número de cuenta aleatorio
    let mut rng = thread_rng();
    let num_cuenta: String = (0..10).map(|_| rng.gen_range(0..=9).to_string()).collect();

    // Insertar cuenta asociada
    if let Err(e) = sqlx::query!(
        "INSERT INTO cuentas (id_usuario, tipo_cuenta, saldo, num_cuenta) VALUES (?, ?, ?, ?)",
        user_id,
        data.tipo_cuenta,
        0.0_f64,
        num_cuenta
    )
        .execute(&mut *tx)
        .await
    {
        tx.rollback().await.ok();
        println!("{}", e);
        return HttpResponse::InternalServerError().json(ApiResponse {
            message: "Error al crear cuenta asociada".into(),
            token: None,
        });
    }

    // Commit
    tx.commit().await.ok();

    HttpResponse::Ok().json(ApiResponse {
        message: format!(
            "Usuario y cuenta creados exitosamente. Número de cuenta: {}",
            num_cuenta
        ),
        token: None,
    })
}


pub async fn login(
    data: web::Json<LoginRequest>,
    pool: web::Data<Pool<MySql>>,
) -> impl Responder {
    println!("{}", data.view_request());
    let user = sqlx::query!("SELECT * FROM usuarios WHERE email = ?", data.email)
        .fetch_one(pool.get_ref())
        .await;

    match user {
        Ok(u) => {
            let password= data.password.trim();

            if password.is_empty(){
                println!("{}", data.fail("La contraseña esta vacia".to_string()));
                return HttpResponse::BadRequest().json(ApiResponse{
                    message: "La contraseña no puede venir vacia".to_string(),
                    token: None,
                });
            }
            //si la consulta devuelve un objeto entonces compara contraseña que mando de data con la del objeto
            let is_valid = bcrypt_verify(&data.password, &u.password).unwrap_or(false);
            if !is_valid {
                data.fail("Contraseña incorrecta".to_string());
                return HttpResponse::Unauthorized().json(ApiResponse {
                    message: "Contraseña incorrecta".into(),
                    token: None,
                });
            }
            println!("{}", data.sucess());
            //token
            let expiration = Utc::now() + Duration::hours(2);
            let claims = Claims {
                sub: u.email.clone(),
                exp: expiration.timestamp() as usize,
            };

            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(SECRET_KEY.as_ref()),
            )
                .unwrap();
            //la clase apiresponse devuelve mensaje de exito con token
            HttpResponse::Ok().json(ApiResponse {
                message: "Inicio de sesión exitoso".into(),
                token: Some(token),
            })
        },
        //si ocurre un error no devuelve nada
        Err(_) => 
            HttpResponse::NotFound().json(ApiResponse {
            message: "Usuario no encontrado".into(),
            token: None,
        }),
    }
}

pub async fn verify(req: HttpRequest) -> impl Responder {
    let token = match req.headers().get("Authorization") {
        Some(h) => h.to_str().unwrap_or("").replace("Bearer ", ""),
        None => "".to_string(),
    };

    if token.is_empty() {
        return HttpResponse::Unauthorized().json(ApiResponse {
            message: "No se proporcionó token".into(),
            token: None,
        });
    }

    let decoded = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(SECRET_KEY.as_ref()),
        &Validation::new(Algorithm::HS256),
    );

    match decoded {
        Ok(data) => HttpResponse::Ok().json(data.claims),
        Err(_) => HttpResponse::Unauthorized().json(ApiResponse {
            message: "Token inválido".into(),
            token: None,
        }),
    }
}

pub async fn get_user_data(req: HttpRequest, pool: web::Data<Pool<MySql>>) -> impl Responder {
    let claims = match decode_token(&req).await {
        Ok(c) => c,
        Err(err) => return err,
    };

    // Consultar usuario y su número de cuenta
    let result = sqlx::query!(
        r#"
        SELECT u.id, u.email, u.usuario,  u.avatar_url, c.num_cuenta, c.tipo_cuenta, c.saldo
        FROM usuarios u
        JOIN cuentas c ON u.id = c.id_usuario
        WHERE u.email = ?
        "#,
        claims.sub
    )
        .fetch_one(pool.get_ref())
        .await;

    match result {
        Ok(r) => {
            // Convertir BigDecimal a String
            let user = UserData {
                id: r.id,
                email: r.email,
                usuario: r.usuario,
                avatar_url: r.avatar_url.unwrap(),
                num_cuenta: r.num_cuenta,
                tipo_cuenta: r.tipo_cuenta,
                saldo: r.saldo.map(|s| s.to_string()),
            };
            HttpResponse::Ok().json(user)
        },
        Err(_) => HttpResponse::NotFound().json(ApiResponse {
            message: "Usuario no encontrado".into(),
            token: None,
        }),
    }
}

pub async fn find_user_by_account_number(
    pool: &Pool<MySql>,
    num_cuenta: &str,
) -> Result<sqlx::mysql::MySqlRow, sqlx::Error> {
    let row = sqlx::query(
        r#"
        SELECT
            u.id AS id_usuario,
            u.email,
            u.usuario,
            u.avatar_url,
            c.id AS id_cuenta,
            c.num_cuenta,
            c.tipo_cuenta,
            c.saldo
        FROM cuentas c
        JOIN usuarios u ON u.id = c.id_usuario
        WHERE c.num_cuenta = ?
        "#,
    )
        .bind(num_cuenta)
        .fetch_one(pool)
        .await?;

    Ok(row)
}

pub async fn transfer(
    req: HttpRequest,
    pool: web::Data<Pool<MySql>>,
    data: web::Json<TransferData>,
) -> impl Responder {
    let claims= match decode_token(&req).await {
      Ok(c)=> c,
        Err(err) => return err,
    };

    // Buscar remitente (usuario logueado)
    let remitente = match sqlx::query!(
        "SELECT id, password FROM usuarios WHERE email = ?",
        claims.sub
    )
        .fetch_one(pool.get_ref())
        .await
    {
        Ok(r) => r,
        Err(_) => {
            return HttpResponse::NotFound().json(ApiResponse {
                message: "Usuario remitente no encontrado".into(),
                token: None,
            });
        }
    };

    // Verificar contraseña
    let is_valid = bcrypt_verify(&data.password, &remitente.password).unwrap_or(false);
    if !is_valid {
        return HttpResponse::Unauthorized().json(ApiResponse {
            message: "Contraseña incorrecta".into(),
            token: None,
        });
    }

    // 4️⃣ Iniciar transacción
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(_) => {
            return HttpResponse::InternalServerError().json(ApiResponse {
                message: "Error iniciando transacción".into(),
                token: None,
            });
        }
    };

    // Obtener cuenta del remitente
    let cuenta_remitente = match sqlx::query!(
        "SELECT id, saldo FROM cuentas WHERE id_usuario = ?",
        remitente.id
    )
        .fetch_one(&mut *tx)
        .await
    {
        Ok(c) => c,
        Err(_) => {
            tx.rollback().await.ok();
            return HttpResponse::NotFound().json(ApiResponse {
                message: "Cuenta del remitente no encontrada".into(),
                token: None,
            });
        }
    };
    
    let saldo_actual = cuenta_remitente.saldo.unwrap_or(BigDecimal::from(0));
    let monto_transfer = BigDecimal::from_str(&data.monto.to_string()).unwrap();

    if saldo_actual < monto_transfer {
        tx.rollback().await.ok();
        return HttpResponse::BadRequest().json(ApiResponse {
            message: "Saldo insuficiente para realizar la transferencia".into(),
            token: None,
        });
    }


    //  Buscar destinatario por número de cuenta
    let destinatario = match find_user_by_account_number(pool.get_ref(), &data.cuenta_destino).await
    {
        Ok(u) => u,
        Err(_) => {
            tx.rollback().await.ok();
            return HttpResponse::NotFound().json(ApiResponse {
                message: "Cuenta de destino no encontrada".into(),
                token: None,
            });
        }
    };

    let id_cuenta_destino: i64 = destinatario.try_get("id_cuenta").unwrap_or(0);
    let saldo_destino: BigDecimal =
        destinatario.try_get("saldo").unwrap_or(BigDecimal::from(0));

    let nuevo_saldo_remitente = &saldo_actual - &monto_transfer;
    let nuevo_saldo_destino = &saldo_destino + &monto_transfer;

    // Registrar movimiento en transferencias
    if let Err(_) = sqlx::query!(
    "INSERT INTO transacciones (id_cuenta, tipo, monto, descripcion) VALUES (?, ?, ?, ?)",
    cuenta_remitente.id,
    "transferencia",
    monto_transfer,
    "Transferencia"
)
        .execute(&mut *tx)
        .await
    {
        tx.rollback().await.ok();
        return HttpResponse::InternalServerError().json(ApiResponse {
            message: "Error al registrar el movimiento".into(),
            token: None,
        });
    }


    if let Err(_) = sqlx::query!(
        "UPDATE cuentas SET saldo = ? WHERE id = ?",
        nuevo_saldo_remitente,
        cuenta_remitente.id
    )
        .execute(&mut *tx)
        .await
    {
        tx.rollback().await.ok();
        return HttpResponse::InternalServerError().json(ApiResponse {
            message: "Error al actualizar saldo del remitente".into(),
            token: None,
        });
    }

    if let Err(_) = sqlx::query!(
        "UPDATE cuentas SET saldo = ? WHERE id = ?",
        nuevo_saldo_destino,
        id_cuenta_destino
    )
        .execute(&mut *tx)
        .await
    {
        tx.rollback().await.ok();
        return HttpResponse::InternalServerError().json(ApiResponse {
            message: "Error al actualizar saldo del destinatario".into(),
            token: None,
        });
    }

    if let Err(_) = tx.commit().await {
        return HttpResponse::InternalServerError().json(ApiResponse {
            message: "Error al confirmar transferencia".into(),
            token: None,
        });
    }

    HttpResponse::Ok().json(ApiResponse {
        message: format!(
            "Transferencia de {:.2} realizada exitosamente a la cuenta {}",
            data.monto, data.cuenta_destino
        ),
        token: None,
    })
}

pub async fn deposit(
    req: HttpRequest,
    pool: web::Data<Pool<MySql>>,
    data: web::Json<DespositData>,
) -> impl Responder {
    let claims= match decode_token(&req).await{
        Ok(c) => c,
        Err(err)=> return err,
    };

    let user = match sqlx::query!("SELECT id, password FROM usuarios WHERE email = ?", claims.sub)
        .fetch_one(pool.get_ref())
        .await
    {
        Ok(u) => u,
        Err(_) => {
            return HttpResponse::NotFound().json(ApiResponse {
                message: "Usuario no encontrado".into(),
                token: None,
            });
        }
    };

    let is_valid = bcrypt_verify(&data.password, &user.password).unwrap_or(false);
    if !is_valid {
        return HttpResponse::Unauthorized().json(ApiResponse {
            message: "Contraseña incorrecta".into(),
            token: None,
        });
    }

    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(_) => {
            return HttpResponse::InternalServerError().json(ApiResponse {
                message: "Error iniciando transacción".into(),
                token: None,
            });
        }
    };

    // Obtener saldo actual
    let cuenta = sqlx::query!(
        "SELECT id, saldo FROM cuentas WHERE id_usuario = ?",
        user.id
    )
        .fetch_one(&mut *tx)
        .await;

    let cuenta = match cuenta {
        Ok(c) => c,
        Err(_) => {
            tx.rollback().await.ok();
            return HttpResponse::NotFound().json(ApiResponse {
                message: "Cuenta no encontrada".into(),
                token: None,
            });
        }
    };

    let saldo_actual = cuenta.saldo.unwrap_or(BigDecimal::from(0));
    let monto_decimal = BigDecimal::from_str(&data.monto.to_string()).unwrap();
    let nuevo_saldo = saldo_actual + monto_decimal.clone();

    let monto_clone= monto_decimal.clone();
    if let Err(_) = sqlx::query!(
    "INSERT INTO transacciones (id_cuenta, tipo, monto, descripcion) VALUES (?, ?, ?, ?)",
    cuenta.id,
    "ingreso",
    monto_clone,
    "Deposito"
)
        .execute(&mut *tx)
        .await
    {
        tx.rollback().await.ok();
        return HttpResponse::InternalServerError().json(ApiResponse {
            message: "Error al registrar el movimiento".into(),
            token: None,
        });
    }
    // Actualizar saldo
    if let Err(_) = sqlx::query!(
        "UPDATE cuentas SET saldo = ? WHERE id = ?",
        nuevo_saldo,
        cuenta.id
    )
        .execute(&mut *tx)
        .await
    {
        tx.rollback().await.ok();
        return HttpResponse::InternalServerError().json(ApiResponse {
            message: "Error al actualizar saldo".into(),
            token: None,
        });
    }

    tx.commit().await.ok();

    HttpResponse::Ok().json(ApiResponse {
        message: format!("Depósito exitoso. Nuevo saldo: {:.2}", nuevo_saldo),
        token: None,
    })
}

pub async fn get_movimientos(req: HttpRequest, pool: web::Data<Pool<MySql>>) -> impl Responder {
    let claims= match decode_token(&req).await {
        Ok(c)=> c,
        Err(err)=> return err,
    };

    // Obtener cuenta del usuario autenticado
    let cuenta = match sqlx::query!(
        "SELECT c.id FROM cuentas c
         JOIN usuarios u ON u.id = c.id_usuario
         WHERE u.email = ?",
        claims.sub
    )
        .fetch_one(pool.get_ref())
        .await
    {
        Ok(c) => c,
        Err(_) => {
            return HttpResponse::NotFound().json(ApiResponse {
                message: "Cuenta no encontrada".into(),
                token: None,
            });
        }
    };

    // Consultar movimientos de la cuenta
    let movimientos = match sqlx::query!(
        r#"
        SELECT id, tipo, monto, descripcion, fecha
        FROM transacciones
        WHERE id_cuenta = ?
        ORDER BY fecha DESC
        "#,
        cuenta.id
    )
        .fetch_all(pool.get_ref())
        .await
    {
        Ok(rows) => rows,
        Err(_) => {
            return HttpResponse::InternalServerError().json(ApiResponse {
                message: "Error al obtener movimientos".into(),
                token: None,
            });
        }
    };

    // Mapear resultados
    let lista: Vec<Movimiento> = movimientos
        .into_iter()
        .map(|r| Movimiento {
            id: r.id,
            tipo: r.tipo,
            monto: r.monto.to_string(),
            descripcion: r.descripcion.unwrap_or_default(),
            fecha: r
                .fecha
                .map(|f| f.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "Sin fecha".to_string()),
        })
        .collect();


    HttpResponse::Ok().json(lista)
}

/// Configuración de rutas
pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/register", web::post().to(register))
        .route("/login", web::post().to(login))
        .route("/verify", web::get().to(verify))
        .route("/data", web::get().to(get_user_data))
        .route("/deposit", web::post().to(deposit))
        .route("/transfer", web::post().to(transfer))
        .route("/movimientos", web::get().to(get_movimientos));
}
