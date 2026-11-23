require("dotenv").config();
const fs = require("fs");
const path = require("path");
const { neon } = require("@neondatabase/serverless");
if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL missing. Create the root .env file.");
  process.exit(1);
}
const sql = neon(process.env.DATABASE_URL);
async function main() {
  const schema = fs.readFileSync(path.join(__dirname, "..", "database", "schema.sql"), "utf8");
  const statements = schema.split(";").map(s => s.trim()).filter(Boolean);
  try {
    for (const statement of statements) await sql.query(statement);
    console.log("Database tables created/verified successfully.");
  } catch (error) {
    console.error("Database setup failed:", error.message);
    process.exitCode = 1;
  }
}
main();
