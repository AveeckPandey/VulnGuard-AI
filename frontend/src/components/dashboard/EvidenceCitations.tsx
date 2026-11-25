import React from 'react';
import { BookOpen, ExternalLink, Shield } from 'lucide-react';

interface EvidenceCitationsProps {
  citations: string[];
}

export const EvidenceCitations: React.FC<EvidenceCitationsProps> = ({ citations }) => {
  if (!citations || citations.length === 0) return null;

  return (
    <div className="surface-panel rounded-2xl p-5">
      <div className="mb-3 flex items-center gap-2">
        <BookOpen className="size-4 text-muted-foreground" />
        <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground">
          Evidence Sources & Verifiable Citations
        </h4>
      </div>

      <div className="flex flex-wrap gap-2">
        {citations.map((cite, idx) => {
          let label = cite;
          let url = cite;
          if (cite.includes('http')) {
            const parts = cite.split('http');
            if (parts[0].includes(':')) {
              label = parts[0].replace(':', '').trim();
              url = `http${parts[1]}`;
            } else {
              url = cite;
              try {
                label = new URL(url).hostname;
              } catch {
                label = url;
              }
            }
          }

          return (
            <a
              key={idx}
              href={url.startsWith('http') ? url : undefined}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-background px-3 py-1.5 text-xs text-zinc-300 transition-colors hover:border-white/[0.16] hover:text-foreground"
            >
              <Shield className="size-3 shrink-0 text-sky-400" />
              <span className="max-w-[240px] truncate font-mono text-[11px]">{label}</span>
              {url.startsWith('http') && <ExternalLink className="size-3 text-muted-foreground" />}
            </a>
          );
        })}
      </div>
    </div>
  );
};
