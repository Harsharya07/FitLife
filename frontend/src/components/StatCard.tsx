import { motion } from 'framer-motion';
import AnimatedCounter from './AnimatedCounter';

interface StatCardProps {
  label: string;
  value: string;
  numericValue?: number;
  icon: React.ReactNode;
  delay?: number;
}

export default function StatCard({ label, value, numericValue, icon, delay = 0 }: StatCardProps) {
  const isNumeric = numericValue !== undefined && !Number.isNaN(numericValue);

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ delay, duration: 0.4 }}
      className="glass-card card-hover rounded-2xl p-6 text-center"
    >
      <div className="gradient-accent mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-2xl text-white shadow-lg shadow-teal-500/25">
        {icon}
      </div>
      <div className="font-display gradient-text text-2xl font-extrabold">
        {isNumeric ? <AnimatedCounter value={numericValue} /> : value}
      </div>
      <div className="mt-1 text-sm font-medium text-muted">{label}</div>
    </motion.div>
  );
}
