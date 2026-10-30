// This worker proposes an action. Only the host broker can validate/authorize it.
let raw = '';
for await (const chunk of process.stdin) raw += chunk;
const input = JSON.parse(raw);
process.stdout.write(JSON.stringify(input.action));
