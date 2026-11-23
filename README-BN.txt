ELITE SPHERE GROUP BANGLADESH — নতুন প্রজেক্ট

১) ZIP extract করে নতুন ফোল্ডার হিসেবে VS Code-এ খুলুন। পুরোনো ফোল্ডারের উপর extract করবেন না।
২) Terminal-এ npm install চালান।
৩) .env.example কপি করে একই জায়গায় .env নাম দিন।
৪) .env-এ Neon থেকে পাওয়া নতুন connection string DATABASE_URL= এর পরে বসান। কাউকে পাঠাবেন না।
৫) npm run db:setup চালান।
৬) npm run dev চালান।
৭) http://localhost:5000 এবং http://localhost:5000/api/health/db খুলে দেখুন।

গুরুত্বপূর্ণ: আগের চ্যাটে DB password প্রকাশিত হয়েছে। Neon থেকে password reset করে নতুন connection string নিন।
এই ZIP-এ backend ও database foundation আছে। Admin login/dashboard এখনো নিরাপদভাবে তৈরি করা হয়নি; সেটি পরের ধাপে করব।
Payment gateway সক্রিয় নয়। .env ফাইল কখনো GitHub-এ দেবেন না।
