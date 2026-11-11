import Collector from "./collector";

const NAV = ["About", "Founder", "Research", "Publications", "News", "Team", "Projects", "Gallery"];

const DOMAINS = [
  { title: "Pattern Recognition", text: "Automated identification and masking of complex data structures and signal analysis." },
  { title: "Generative AI & LLMs", text: "Large language models, generative systems and human-centric applications." },
  { title: "Network Security", text: "Detecting VPNs, proxies and anonymised traffic with device-anchored measurements." },
  { title: "Healthcare AI", text: "Deep learning for medical signals and imaging that supports clinical decisions." },
  { title: "Cognitive Gaming", text: "Games and interactive systems that model attention, learning and behaviour." },
  { title: "Human-Robot Interaction", text: "Agentic and embodied systems that work alongside people." },
];

const NOTICES = [
  { date: "SEP 24, 2026", title: "Research collaboration visit", text: "Members of the lab visited partner institutes to plan joint research on responsible AI." },
  { date: "AUG 12, 2026", title: "Internship openings", text: "Applications are open for research interns working on deep learning and security." },
  { date: "JUL 03, 2026", title: "Workshop on network measurement", text: "A hands-on workshop on privacy-preserving network and browser measurement." },
];

const APPROACH = [
  { step: "Data", text: "Curating and understanding real-world signals." },
  { step: "Model", text: "Designing deep, generative and agentic architectures." },
  { step: "Validate", text: "Rigorous, reproducible and responsible evaluation." },
  { step: "Deploy", text: "Turning research into measurable societal impact." },
];

export default function Home() {
  return (
    <>
      <Collector />

      <div className="sticky top-0 z-20 border-b border-[#eaecf0] bg-white/85 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-3 sm:px-6">
          <div className="h-12 w-12 shrink-0 rounded-full bg-gradient-to-br from-[#7c5cff] to-[#22d3ee]" aria-hidden />
          <div className="text-center">
            <p className="text-base font-bold uppercase tracking-tight text-[#101828] sm:text-lg">Deep Learning Lab</p>
            <p className="text-[10px] font-medium uppercase tracking-[0.2em] text-[#4f46e5] sm:text-xs">Imagine · Believe · Achieve</p>
          </div>
          <p className="hidden text-right text-[11px] font-bold uppercase leading-4 text-[#101828] sm:block">
            Research group<br />Department of Computer Science
          </p>
        </div>
        <nav className="border-t border-[#f2f4f7]">
          <ul className="mx-auto flex max-w-6xl gap-1 overflow-x-auto px-4 py-2 text-sm font-medium text-[#344054] sm:justify-center sm:px-6">
            {NAV.map((item) => (
              <li key={item}><a href={`#${item.toLowerCase()}`} className="block whitespace-nowrap rounded-lg px-3 py-1.5 hover:bg-[#f2f4f7]">{item}</a></li>
            ))}
          </ul>
        </nav>
      </div>

      <main>
        <section id="hero" className="relative flex min-h-[560px] items-end bg-[#101828] bg-[radial-gradient(ellipse_at_top_right,#3b3f8f_0%,#101828_60%)]">
          <div className="mx-auto w-full max-w-6xl px-4 pb-16 sm:px-6">
            <h1 className="max-w-2xl font-serif text-4xl font-semibold leading-tight text-white sm:text-5xl">
              Advancing research in Deep Learning &amp; Artificial Intelligence
            </h1>
            <p className="mt-4 max-w-xl text-base leading-7 text-[#d0d5dd]">
              A multidisciplinary research group building AI systems that make a measurable difference, from healthcare to cybersecurity.
            </p>
          </div>
        </section>

        <section id="about" className="mx-auto max-w-6xl px-4 py-20 sm:px-6">
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-[#4f46e5]">Who we are</p>
          <h2 className="mt-2 font-serif text-3xl font-semibold text-[#101828]">About the Lab</h2>
          <p className="mt-4 max-w-3xl text-base leading-7 text-[#475467]">
            The Deep Learning Lab is a multidisciplinary research group advancing cutting-edge Artificial Intelligence and
            human-centric applications. Our research spans generative AI, cognitive gaming, human-robot interaction and
            network security, with a focus on work that is reproducible, responsible and useful.
          </p>
        </section>

        <section id="research" className="bg-white py-20">
          <div className="mx-auto max-w-6xl px-4 sm:px-6">
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-[#4f46e5]">What we explore</p>
            <h2 className="mt-2 font-serif text-3xl font-semibold text-[#101828]">Research Domains</h2>
            <p className="mt-2 text-[#475467]">Exploring the future of intelligence through diverse, applied research areas.</p>
            <div className="mt-8 grid gap-5 sm:grid-cols-2 lg:grid-cols-3">
              {DOMAINS.map((domain) => (
                <div key={domain.title} className="rounded-2xl border border-[#eaecf0] bg-[#fafafa] p-6">
                  <h3 className="font-semibold text-[#101828]">{domain.title}</h3>
                  <p className="mt-2 text-sm leading-6 text-[#475467]">{domain.text}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="news" className="mx-auto max-w-6xl px-4 py-20 sm:px-6">
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-[#4f46e5]">Notice board</p>
          <h2 className="mt-2 font-serif text-3xl font-semibold text-[#101828]">Latest Notices</h2>
          <p className="mt-2 text-[#475467]">Internships, workshops, openings and circulars.</p>
          <div className="mt-8 grid gap-5 md:grid-cols-3">
            {NOTICES.map((notice) => (
              <article key={notice.title} className="rounded-2xl border border-[#eaecf0] bg-white p-6 shadow-sm">
                <p className="text-xs font-semibold tracking-wide text-[#4f46e5]">{notice.date}</p>
                <h3 className="mt-2 font-semibold text-[#101828]">{notice.title}</h3>
                <p className="mt-2 text-sm leading-6 text-[#475467]">{notice.text}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="bg-white py-20">
          <div className="mx-auto max-w-6xl px-4 sm:px-6">
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-[#4f46e5]">Our approach</p>
            <h2 className="mt-2 font-serif text-3xl font-semibold text-[#101828]">From Idea to Impact</h2>
            <div className="mt-8 grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
              {APPROACH.map((item, index) => (
                <div key={item.step} className="rounded-2xl border border-[#eaecf0] p-6">
                  <p className="text-sm font-semibold text-[#4f46e5]">0{index + 1}</p>
                  <h3 className="mt-1 font-semibold text-[#101828]">{item.step}</h3>
                  <p className="mt-2 text-sm leading-6 text-[#475467]">{item.text}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="mx-auto max-w-6xl px-4 py-20 text-center sm:px-6">
          <p className="text-xs font-semibold uppercase tracking-[0.2em] text-[#4f46e5]">Join the lab</p>
          <h2 className="mx-auto mt-2 max-w-2xl font-serif text-3xl font-semibold text-[#101828]">Let&apos;s build the next generation of responsible AI together</h2>
          <p className="mx-auto mt-3 max-w-xl text-[#475467]">Collaborate with us on research, projects and publications.</p>
          <a href="#contact" className="mt-6 inline-block rounded-xl bg-[#4f46e5] px-6 py-3 text-sm font-semibold text-white hover:bg-[#4338ca]">Get in touch</a>
        </section>
      </main>

      <footer id="contact" className="bg-[#0d1220] text-[#98a2b3]">
        <div className="mx-auto grid max-w-6xl gap-10 px-4 py-14 sm:grid-cols-3 sm:px-6">
          <div>
            <p className="font-bold uppercase text-white">Deep Learning Lab</p>
            <p className="mt-1 text-xs uppercase tracking-[0.2em]">Imagine · Believe · Achieve</p>
            <p className="mt-4 text-sm leading-6">Advancing research in artificial intelligence and deep neural networks.</p>
          </div>
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-white">Explore</p>
            <ul className="mt-4 space-y-2 text-sm">
              {NAV.map((item) => <li key={item}>{item}</li>)}
            </ul>
          </div>
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-white">Contact</p>
            <p className="mt-4 text-sm leading-6">Your lab email address<br />Your institute address</p>
          </div>
        </div>
        <div className="border-t border-[#1d2939] px-4 py-5 text-center text-xs sm:px-6">
          <p>© 2026 Deep Learning Lab. All rights reserved.</p>
          <p className="mt-1">This site records technical connection and device data for academic research on VPN detection.</p>
        </div>
      </footer>
    </>
  );
}
