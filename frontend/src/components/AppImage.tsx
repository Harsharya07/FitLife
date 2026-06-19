import { useState } from 'react';

interface AppImageProps extends React.ImgHTMLAttributes<HTMLImageElement> {
  src: string;
  alt: string;
}

export default function AppImage({ src, alt, className, ...props }: AppImageProps) {
  const [error, setError] = useState(false);
  const resolved = error ? '/images/placeholder.jpg' : src;

  return (
    <img
      {...props}
      src={resolved}
      alt={alt}
      className={className}
      loading="lazy"
      decoding="async"
      onError={() => setError(true)}
    />
  );
}
