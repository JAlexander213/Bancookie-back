mod models;
mod controller;
mod interfaces;

mod lib;

use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use dotenvy::dotenv;
use sqlx::{MySql, Pool};
use std::env;
use actix_web::web::route;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL no configurada");
    let pool = Pool::<MySql>::connect(&database_url)
        .await
        .expect("Error al conectar a la base de datos");

    println!("Servidor corriendo en http://127.0.0.1:8080/");

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
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
