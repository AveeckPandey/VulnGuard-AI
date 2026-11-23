import React from 'react';
import { BookOpen, ExternalLink, Shield } from 'lucide-react';

interface EvidenceCitationsProps {
  citations: string[];
}

export const EvidenceCitations: React.FC<EvidenceCitationsProps> = ({ citations }) => {
  if (!citations || citations.length === 0) return null;

  return (
    <div className="p-5 rounded-2xl bg-card border border-border shadow-md">
      <div className="flex items-center space-x-2 mb-3">
        <BookOpen className="w-4 h-4 text-sky-400" />
        <h4 className="text-xs font-bold uppercase tracking-wider text-white">
          Evidence Sources & Verifiable Citations
        </h4>
      </div>

      <div className="flex flex-wrap gap-2">
        {citations.map((cite, idx) => {
          // If cite has format "Source: URL" or bare URL
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
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-[#0b1120] border border-slate-800 text-slate-300 hover:text-sky-300 hover:border-slate-700 text-xs transition-all"
            >
              <Shield className="w-3 h-3 text-sky-400 shrink-0" />
              <span className="font-mono text-[11px] truncate max-w-[240px]">{label}</span>
              {url.startsWith('http') && <ExternalLink className="w-3 h-3 text-slate-500" />}
            </a>
          );
        })}
      </div>
    </div>
  );
};
