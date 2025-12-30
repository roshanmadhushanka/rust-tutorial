mod configuration;

use secrecy::ExposeSecret;
use crate::configuration::Configuration;

fn main() {
    let settings = Configuration::new();
    println!("Exposing JWT Secret {}", settings.unwrap().application.jwt_secret.expose_secret());
}
