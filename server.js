const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());

const PORT = 4000;
const JWT_SECRET = "change-this-secret-later";

app.post("/signup", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: "Email and password required"
            });
        }

        const existingUser = await prisma.user.findUnique({
            where: { email }
        });

        if (existingUser) {
            return res.status(400).json({
                message: "User already exists"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await prisma.user.create({
            data: {
                email,
                password: hashedPassword
            }
        });

        res.json({
            message: "User created",
            user: {
                id: user.id,
                email: user.email
            }
        });
    } catch (err) {
        console.log(err);
        res.status(500).json({
            message: "Server error"
        });
    }
});

app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await prisma.user.findUnique({
            where: { email }
        });

        if (!user) {
            return res.status(400).json({
                message: "Invalid login"
            });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(400).json({
                message: "Invalid login"
            });
        }

        const token = jwt.sign(
            {
                id: user.id,
                email: user.email,
                role: user.role
            },
            JWT_SECRET,
            {
                expiresIn: "7d"
            }
        );

        res.json({
            token,
            user: {
                id: user.id,
                email: user.email,
                role: user.role
            }
        });
    } catch (err) {
        console.log(err);
        res.status(500).json({
            message: "Server error"
        });
    }
});

// Updated to include answers and application status
app.get("/console/users", async (req, res) => {
    try {
        const users = await prisma.user.findMany({
            select: {
                id: true,
                email: true,
                role: true,
                applicationAnswer: true,
                applicationStatus: true,
                createdAt: true
            }
        });

        res.json(users);
    } catch (err) {
        console.log(err);
        res.status(500).json({
            message: "Server error"
        });
    }
});

// Submit Application Route
app.post("/apply", async (req, res) => {
    try {
        const { email, answer } = req.body;

        const user = await prisma.user.update({
            where: { email },
            data: {
                applicationAnswer: answer,
                applicationStatus: "pending"
            }
        });

        res.json({ message: "Application submitted", user });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Server error" });
    }
});

// Updated to listen properly across all network interfaces
app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
});