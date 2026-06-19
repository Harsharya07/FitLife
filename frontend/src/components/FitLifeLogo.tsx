import { Link } from 'react-router-dom';
import { IMAGES } from '../lib/images';

const SIZES = {
  sm: { icon: 'h-8 w-8', text: 'text-lg' },
  md: { icon: 'h-10 w-10', text: 'text-xl sm:text-2xl' },
  lg: { icon: 'h-14 w-14', text: 'text-2xl sm:text-3xl' },
} as const;

interface FitLifeLogoProps {
  size?: keyof typeof SIZES;
  showText?: boolean;
  to?: string;
  className?: string;
  textClassName?: string;
  ring?: boolean;
}

export default function FitLifeLogo({
  size = 'md',
  showText = true,
  to = '/',
  className = '',
  textClassName = '',
  ring = false,
}: FitLifeLogoProps) {
  const { icon, text } = SIZES[size];

  const content = (
    <>
      <img
        src={IMAGES.logo}
        alt=""
        aria-hidden
        className={`${icon} shrink-0 rounded-xl object-cover ${ring ? 'ring-2 ring-white/30' : ''}`}
      />
      {showText && (
        <span className={`font-display font-extrabold tracking-tight ${text} ${textClassName}`}>
          Fit<span className="text-teal-300">Life</span>
        </span>
      )}
    </>
  );

  if (to) {
    return (
      <Link to={to} className={`group flex shrink-0 items-center gap-2.5 ${className}`} aria-label="FitLife home">
        {content}
      </Link>
    );
  }

  return <div className={`flex shrink-0 items-center gap-2.5 ${className}`}>{content}</div>;
}
