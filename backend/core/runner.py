"""
Generic async external-tool runner.
Every scanner module builds a command list and calls run_tool().
Handles timeout, retries, and streams stdout lines to an async callback
(used later for websocket live-logs).
"""
import asyncio
import logging

logger = logging.getLogger("runner")


async def run_tool(
    cmd: list[str],
    timeout: int = 300,
    retries: int = 1,
    input_data: str | None = None,
    on_line=None,
) -> str:
    """
    Run a command, return combined stdout.
    on_line: optional async callback(line: str) invoked per stdout line,
             used to stream progress to UI/websocket.
    """
    last_err = None
    for attempt in range(1, retries + 2):
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            if input_data:
                proc.stdin.write(input_data.encode())
                await proc.stdin.drain()
                proc.stdin.close()

            output_lines = []

            async def read_stream():
                async for raw in proc.stdout:
                    line = raw.decode(errors="ignore").rstrip("\n")
                    output_lines.append(line)
                    if on_line:
                        await on_line(line)

            try:
                await asyncio.wait_for(read_stream(), timeout=timeout)
                await proc.wait()
            except asyncio.TimeoutError:
                proc.kill()
                raise

            if proc.returncode not in (0, None):
                stderr = (await proc.stderr.read()).decode(errors="ignore")
                logger.warning("cmd %s exited %s: %s", cmd[0], proc.returncode, stderr[:400])

            return "\n".join(output_lines)

        except FileNotFoundError:
            logger.error("Binary not found: %s", cmd[0])
            return ""
        except asyncio.TimeoutError as e:
            last_err = e
            logger.warning("Attempt %d/%d timed out for %s", attempt, retries + 1, cmd[0])
        except Exception as e:  # noqa
            last_err = e
            logger.warning("Attempt %d/%d failed for %s: %s", attempt, retries + 1, cmd[0], e)

    logger.error("All attempts failed for %s: %s", cmd, last_err)
    return ""
