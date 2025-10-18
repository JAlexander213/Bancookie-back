mod models;
mod controller;
mod interfaces;

mod lib;

use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use dotenvy::dotenv;
use sqlx::{MySql, Pool};
use std::env;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    // Conexión a la base de datos
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL no configurada");
    let pool = Pool::<MySql>::connect(&database_url)
        .await
        .expect("Error al conectar a la base de datos");

    // Obtener el puerto desde Render (o usar 8080 localmente)
    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .expect("PORT debe ser un número");

    println!("Servidor corriendo en http://0.0.0.0:{}/", port);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .supports_credentials();

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(pool.clone()))
            .configure(controller::routes)
    })
    .bind(("0.0.0.0", port))? // <- Muy importante para Render
    .run()
    .await
}
