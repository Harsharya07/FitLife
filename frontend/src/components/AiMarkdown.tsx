import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

interface AiMarkdownProps {
  content: string;
  className?: string;
}

export default function AiMarkdown({ content, className = '' }: AiMarkdownProps) {
  return (
    <div className={`ai-markdown prose prose-sm max-w-none sm:prose-base ${className}`}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({ children }) => (
            <h1 className="font-display mb-3 mt-4 text-xl font-bold text-primary">{children}</h1>
          ),
          h2: ({ children }) => (
            <h2 className="font-display mb-2 mt-4 text-lg font-bold text-primary">{children}</h2>
          ),
          h3: ({ children }) => (
            <h3 className="mb-2 mt-3 font-bold text-secondary">{children}</h3>
          ),
          p: ({ children }) => <p className="mb-2 leading-relaxed text-ink/90">{children}</p>,
          ul: ({ children }) => <ul className="mb-3 list-disc space-y-1 pl-5">{children}</ul>,
          ol: ({ children }) => <ol className="mb-3 list-decimal space-y-1 pl-5">{children}</ol>,
          li: ({ children }) => <li className="text-ink/90">{children}</li>,
          strong: ({ children }) => <strong className="font-bold text-primary">{children}</strong>,
          table: ({ children }) => (
            <div className="my-4 overflow-x-auto rounded-xl border border-[#e0c3fc]">
              <table className="min-w-full text-left text-sm">{children}</table>
            </div>
          ),
          th: ({ children }) => (
            <th className="bg-primary/10 px-3 py-2 font-bold text-primary">{children}</th>
          ),
          td: ({ children }) => <td className="border-t border-[#e0c3fc]/50 px-3 py-2">{children}</td>,
          code: ({ children }) => (
            <code className="rounded bg-[#f0ebf8] px-1.5 py-0.5 text-sm text-primary">{children}</code>
          ),
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
