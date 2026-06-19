import { Heart } from 'lucide-react';
import { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { extrasApi } from '../lib/api';

interface FavoriteButtonProps {
  itemType: string;
  itemId: string;
  className?: string;
}

export default function FavoriteButton({ itemType, itemId, className = '' }: FavoriteButtonProps) {
  const [favorited, setFavorited] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    extrasApi.isFavorite(itemType, itemId).then(setFavorited).catch(() => null);
  }, [itemType, itemId]);

  const toggle = async (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (loading) return;
    setLoading(true);
    try {
      if (favorited) {
        await extrasApi.removeFavorite(itemType, itemId);
        setFavorited(false);
        toast.success('Removed from favorites');
      } else {
        await extrasApi.addFavorite(itemType, itemId);
        setFavorited(true);
        toast.success('Added to favorites');
      }
    } catch {
      toast.error('Could not update favorite');
    } finally {
      setLoading(false);
    }
  };

  return (
    <button
      onClick={toggle}
      disabled={loading}
      className={`rounded-full p-2 transition hover:bg-surface-2 disabled:opacity-50 ${className}`}
      aria-label={favorited ? 'Remove favorite' : 'Add favorite'}
    >
      <Heart
        size={18}
        className={favorited ? 'fill-red-500 text-red-500' : 'text-muted'}
      />
    </button>
  );
}
