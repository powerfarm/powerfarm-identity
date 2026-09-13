import { redirect } from "next/navigation";

type IdentityHomeProps = {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
};

export default async function IdentityHome({ searchParams }: IdentityHomeProps) {
  const { code } = await searchParams;
  // A magic link falls back to the Site URL when its callback is not allowlisted; keep the code.
  if (typeof code === "string" && code) redirect(`/auth/callback?${new URLSearchParams({ code })}`);
  redirect("/login");
}
