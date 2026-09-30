import type { Metadata } from "next";
import "./globals.css";
import {SITE_URL} from "@/lib/site";

export const metadata: Metadata = {
  title: "ThreatLens AI — URL Intelligence",
  description: "Investigate URLs with transparent model evidence and domain intelligence.",
  metadataBase: new URL(SITE_URL),
  alternates: {canonical: '/'},
  robots: {index:true,follow:true},
  openGraph: {title:'ThreatLens AI — URL Intelligence',description:'Check suspicious links, explore model evidence, and save your own investigation notes.',type:'website',siteName:'ThreatLens AI',url:SITE_URL},
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
