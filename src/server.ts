import { createGatewayServer } from './app.js';
import { loadConfig } from './config.js';

const config = loadConfig();
const { server } = createGatewayServer(config);

server.listen(config.port, config.host, () => {
  console.log(`auth-mini-gateway listening on ${config.host}:${config.port}`);
});
