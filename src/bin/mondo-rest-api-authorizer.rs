//! The packaged Mondo REST API token authorizer, configured from `MONDO_*` environment variables.

use mondo_lambda_authorizer::logging;
use mondo_lambda_authorizer::rest_api::{self, Authorizer};

#[tokio::main]
async fn main() -> Result<(), lambda_runtime::Error> {
    logging::init();

    rest_api::run(Authorizer::from_env()?).await
}
