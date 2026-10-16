//! Entry point: acquire the Edge session, then serve MCP over stdio.

use clap::Parser;
use omb_atlassian_mcp::{
    Error,
    atlassian::{Client, JIRA_MYSELF, Site},
    cli::Args,
    log, session,
    tools::{AtlassianServer, TOOL_SPECS},
};
use rmcp::ServiceExt;

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if let Err(error) = run(args).await {
        log!("error: {error}");
        std::process::exit(1);
    }
}

async fn run(args: Args) -> omb_atlassian_mcp::Result<()> {
    // Reject levels that are declared but not built before touching anything else, so
    // an unsupported --access-level can never widen what the agent may do.
    let level = args.access_level.ensure_implemented()?;
    let site = Site::parse(&args.site)?;

    let session = session::acquire(&site, &args.profile).await?;
    log!(
        "using the Edge session for {} ({} cookie(s): {}), access level {}",
        site.host(),
        session.cookie_names.len(),
        session.cookie_names.join(", "),
        level
    );

    let client = Client::new(site, level, session.cookie_header)?;

    // `--check` gives a way to prove the cookie path works without an MCP client.
    if args.check {
        let identity = client.get_json(JIRA_MYSELF, &[]).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&identity).unwrap_or_else(|_| identity.to_string())
        );
        log!("session is valid");
        return Ok(());
    }

    let server = AtlassianServer::new(client, level);
    log!("serving {} read-only tools over stdio", TOOL_SPECS.len());

    let running = server
        .serve(rmcp::transport::stdio())
        .await
        .map_err(|error| Error::Mcp(error.to_string()))?;
    running
        .waiting()
        .await
        .map_err(|error| Error::Mcp(error.to_string()))?;
    Ok(())
}
