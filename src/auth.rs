use biscuit_auth::{Biscuit, PublicKey};
use http::{header::AUTHORIZATION, Request};
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[derive(Debug, Clone)]
pub struct ParseBiscuit {
    public_key: PublicKey,
}

impl ParseBiscuit {
    pub fn new(public_key: PublicKey) -> ParseBiscuit {
        ParseBiscuit { public_key }
    }
}

impl<S> Layer<S> for ParseBiscuit {
    type Service = ParseBiscuitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ParseBiscuitService::new(inner, self.public_key)
    }
}

#[derive(Debug, Clone)]
pub struct ParseBiscuitService<S> {
    inner: S,
    public_key: PublicKey,
}

impl<S> ParseBiscuitService<S> {
    pub fn new(inner: S, public_key: PublicKey) -> Self {
        ParseBiscuitService { inner, public_key }
    }
}

impl<S, B> Service<Request<B>> for ParseBiscuitService<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let token_str = request
            .headers()
            .get(AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap()
            .strip_prefix("Bearer ")
            .unwrap();
        let token = Biscuit::from_base64(token_str, self.public_key).unwrap();
        request.extensions_mut().insert(token);
        self.inner.call(request)
    }
}
