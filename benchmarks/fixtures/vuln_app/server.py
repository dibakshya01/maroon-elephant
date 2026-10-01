from mcp.server.fastmcp import FastMCP
mcp = FastMCP("demo")
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(mcp, host="0.0.0.0", port=8000)  # binds 0.0.0.0
