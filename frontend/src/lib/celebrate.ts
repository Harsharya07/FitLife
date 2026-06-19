import toast from 'react-hot-toast';

export function celebrate(message: string) {
  toast.success(message, { duration: 4000, icon: '🎉' });
}

export function streakMilestone(streak: number) {
  if ([3, 7, 14, 30].includes(streak)) {
    toast.success(`${streak}-day streak! Keep it going!`, { duration: 5000, icon: '🔥' });
  }
}
