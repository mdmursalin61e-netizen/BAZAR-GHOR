require("dotenv").config();
const { neon } = require("@neondatabase/serverless");
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is missing. Create .env in the project root.");
const sql = neon(process.env.DATABASE_URL);
async function testConnection() {
  const result = await sql`SELECT NOW() AS current_time`;
  return result[0].current_time;
}
module.exports = { sql, testConnection };
