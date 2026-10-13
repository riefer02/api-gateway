use crate::state::AppState;
use axum::extract::State;

pub(crate) async fn person(State(state): State<AppState>) -> String {
    let url = format!("{}/people/1", state.swapi_base_url);
    let response = state
        .client
        .get(&url)
        .send()
        .await
        .unwrap();
    response.text().await.unwrap()
}
