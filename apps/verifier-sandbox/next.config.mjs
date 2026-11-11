/** @type {import('next').NextConfig} */
const rawBasePath = (process.env.NEXT_PUBLIC_BASE_PATH || "").replace(/\/+$/, "");

const nextConfig = {
  reactStrictMode: true,
  output: "export",
  trailingSlash: true,
  basePath: rawBasePath,
  assetPrefix: rawBasePath || undefined,
  images: {
    unoptimized: true,
  },
};

export default nextConfig;
