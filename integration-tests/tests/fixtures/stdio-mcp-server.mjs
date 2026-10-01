// Official MCP v2 stdio server gated by DrsGatedServerTransport. Spawned by
// protocols.live.test.mjs. Executed tool calls are reported on stderr so the
// test can prove what actually ran.
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { createDrsGate, DrsGatedServerTransport } from "@drs/mcp-server";
import { makeMcpServer, VERIFY_URL } from "../live-harness.mjs";

const executed = {
  push: (entry) => process.stderr.write(`EXECUTED ${entry}\n`),
};
const gate = createDrsGate({ verifyUrl: VERIFY_URL, protocol: "mcp" });
await makeMcpServer(executed).connect(
  new DrsGatedServerTransport(new StdioServerTransport(), gate),
);
