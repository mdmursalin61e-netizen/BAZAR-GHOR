require("dotenv").config();

const { neon } = require("@neondatabase/serverless");

const databaseUrl = String(process.env.DATABASE_URL || "").trim();

if (!databaseUrl) {
    throw new Error(
        "[BAZAR GHOR] DATABASE_URL is missing. Create .env in the project root."
    );
}

const sql = neon(databaseUrl);

async function testConnection() {
    const result = await sql`SELECT NOW() AS current_time`;
    return result[0].current_time;
}

module.exports = { sql, testConnection };