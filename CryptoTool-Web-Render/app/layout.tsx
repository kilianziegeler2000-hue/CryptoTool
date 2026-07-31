import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geist = Geist({ variable: "--font-geist", subsets: ["latin"] });
const mono = Geist_Mono({ variable: "--font-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: "CryptoTool – lokale Dateiverschlüsselung",
  description: "Dateien lokal im Browser verschlüsseln, entschlüsseln und prüfen.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="de"><body className={`${geist.variable} ${mono.variable}`}>{children}</body></html>;
}
