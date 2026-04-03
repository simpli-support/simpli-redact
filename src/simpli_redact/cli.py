"""CLI interface."""

import typer
import uvicorn

from simpli_redact import __version__
from simpli_redact.settings import settings

app = typer.Typer(help="Simpli Redact CLI")


@app.command()
def serve(
    host: str = typer.Option(settings.app_host, help="Bind host"),
    port: int = typer.Option(settings.app_port, help="Bind port"),
    reload: bool = typer.Option(settings.app_debug, help="Enable auto-reload"),
) -> None:
    """Start the API server."""
    uvicorn.run(
        "simpli_redact.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level=settings.app_log_level,
    )


@app.command()
def version() -> None:
    """Show version."""
    typer.echo(f"simpli-redact {__version__}")
