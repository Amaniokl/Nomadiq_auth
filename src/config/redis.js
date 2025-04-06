import { createClient } from 'redis';
import dotenv from 'dotenv';

dotenv.config();

const redisClient = createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6380',
});

redisClient.on('error', (err) => console.error('❌ Redis Error:', err));

redisClient.connect().then(() => console.log('✅ Redis Connected'));

export { redisClient };
