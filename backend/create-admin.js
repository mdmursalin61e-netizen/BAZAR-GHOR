require("dotenv").config();

const bcrypt = require("bcryptjs");
const { sql } = require("./db");

async function createAdmin() {
    try {
        const name = String(process.env.ADMIN_NAME || "").trim();
        const email = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
        const password = String(process.env.ADMIN_PASSWORD || "");

        if (!name || !email || !password) {
            throw new Error(
                "ADMIN_NAME, ADMIN_EMAIL and ADMIN_PASSWORD must be set in .env"
            );
        }

        if (password.length < 12) {
            throw new Error("Admin password must be at least 12 characters.");
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const existing = await sql`
            SELECT id FROM admins WHERE LOWER(email) = ${email}
        `;

        if (existing.length > 0) {
            console.log(`[BAZAR GHOR] Admin account (${email}) already exists. No changes made.`);
            return;
        }

        await sql`
            INSERT INTO admins (name, email, password_hash)
            VALUES (${name}, ${email}, ${passwordHash})
        `;

        console.log(`[BAZAR GHOR] Admin account (${email}) created successfully.`);
    } catch (error) {
        console.error("[BAZAR GHOR] Admin creation failed:", error.message);
        process.exitCode = 1;
    }
}

createAdmin();