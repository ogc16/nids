/** @type {import('next').NextConfig} */
const nextConfig = {
  serverExternalPackages: ['better-sqlite3', 'bcryptjs', 'ssh2'],
};

module.exports = nextConfig;
