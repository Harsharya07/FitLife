import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import StatCard from '../components/StatCard';

describe('StatCard', () => {
  it('renders label and value', () => {
    render(<StatCard label="Workouts" value="12" icon={<span>icon</span>} delay={0} />);
    expect(screen.getByText('Workouts')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();
  });
});
