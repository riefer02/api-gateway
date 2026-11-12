mod admin;
mod app;
mod auth;
mod config;
mod db;
mod error;
mod observability;
mod proxy;
mod request_context;
mod routes;
mod routing;
mod serve;
mod state;

#[cfg(test)]
mod testing;

use std::process::ExitCode;

use clap::Parser;

use crate::admin::cli::{Cli, Command};

#[tokio::main]
async fn main() -> ExitCode {
    // Local development convenience; real deployments inject the environment.
    dotenvy::dotenv().ok();

    let command = Cli::parse().command;

    let outcome = match command {
        Command::Serve(args) => serve::run(args).await,
        Command::Admin(args) => admin::cli::run(args).await,
    };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
