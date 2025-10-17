"""
FBL Worker - FastAPI subprocess worker for FBL parser

Receives email parsing requests from Bento via HTTP and returns parsed events.
"""

import email
import logging
from typing import Any, Dict, List, Optional

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Histogram, generate_latest
from pydantic import BaseModel, Field

from parsers.fbl import EmailMessage, FBLEvent, ParserError, parse_fbl

# Initialize structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# Prometheus metrics
fbl_parse_requests = Counter("fbl_parse_requests_total", "Total FBL parse requests", ["status"])
fbl_parse_duration = Histogram("fbl_parse_duration_seconds", "FBL parse duration")
fbl_parse_errors = Counter("fbl_parse_errors_total", "Total FBL parse errors", ["error_type"])

app = FastAPI(
    title="FBL Parser Worker",
    description="FastAPI worker for parsing FBL (Feedback Loop) emails",
    version="0.1.0",
)


class ParseRequest(BaseModel):
    """Email parsing request from Bento"""

    message: str = Field(..., description="Raw email message (RFC 5322 format)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Email metadata from Kafka")
    tags: List[str] = Field(default_factory=list, description="Message tags")


class ParseResponse(BaseModel):
    """Parsed FBL event response"""

    events: List[FBLEvent]
    parser: str = "fbl"
    success: bool = True


class ErrorResponse(BaseModel):
    """Error response"""

    error: str
    error_type: str
    success: bool = False


@app.get("/health")
async def health() -> Dict[str, str]:
    """Health check endpoint"""
    return {"status": "healthy", "parser": "fbl"}


@app.get("/metrics")
async def metrics() -> Any:
    """Prometheus metrics endpoint"""
    return generate_latest()


@app.post("/parse", response_model=ParseResponse)
async def parse_email(request: ParseRequest) -> ParseResponse:
    """
    Parse FBL email and extract events

    Args:
        request: Email parsing request with raw message and metadata

    Returns:
        Parsed FBL events or error
    """
    with fbl_parse_duration.time():
        try:
            # Parse raw email bytes
            parsed_message = email.message_from_bytes(request.message.encode("utf-8"))

            # Extract headers
            headers: Dict[str, List[str]] = {}
            for key, value in parsed_message.items():
                lower_key = key.lower()
                if lower_key not in headers:
                    headers[lower_key] = []
                headers[lower_key].append(value)

            # Build EmailMessage object
            email_msg = EmailMessage(
                headers=headers,
                metadata=request.metadata,
                parsed_message=parsed_message,
                parts=[],  # Will be populated if multipart
            )

            # Extract from address
            from_header = headers.get("from", [""])[0]
            from_addr = email.utils.parseaddr(from_header)[1] if from_header else ""

            if not from_addr:
                fbl_parse_errors.labels(error_type="no_from_address").inc()
                raise HTTPException(status_code=400, detail="No From address found")

            # Parse FBL event
            fbl_event = parse_fbl(email_msg, from_addr)

            if not fbl_event:
                fbl_parse_requests.labels(status="rejected").inc()
                logger.info("fbl_email_rejected", reason="not_fbl_email")
                return ParseResponse(events=[], success=True)

            fbl_parse_requests.labels(status="success").inc()
            logger.info(
                "fbl_email_parsed",
                ip=fbl_event.ip,
                url=fbl_event.url,
                cfbl_address=fbl_event.headers.get("cfbl-address", []),
            )

            return ParseResponse(events=[fbl_event], success=True)

        except ParserError as e:
            fbl_parse_requests.labels(status="parser_error").inc()
            fbl_parse_errors.labels(error_type=str(e).split(":")[0]).inc()
            logger.warning("fbl_parser_error", error=str(e))

            # Return empty events (not HTTP error) - email is rejected but not failed
            return ParseResponse(events=[], success=True)

        except Exception as e:
            fbl_parse_requests.labels(status="error").inc()
            fbl_parse_errors.labels(error_type="unexpected").inc()
            logger.error("fbl_parse_unexpected_error", error=str(e), exc_info=True)

            raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Custom HTTP exception handler"""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(error=exc.detail, error_type="http_error").model_dump(),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")
