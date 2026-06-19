import { motion } from 'framer-motion';
import { Clock, Globe, Mail, MapPin, Phone, Send, User } from 'lucide-react';
import { useState } from 'react';
import toast from 'react-hot-toast';
import axios from 'axios';
import { contactApi } from '../lib/api';
import PageHero from '../components/PageHero';

export default function ContactPage() {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    try {
      const res = await contactApi.submit({ name, email, message });
      toast.success(res.message);
      setName('');
      setEmail('');
      setMessage('');
    } catch (err) {
      const msg = axios.isAxiosError(err)
        ? err.response?.data?.detail || 'Failed to send message'
        : 'Failed to send message';
      toast.error(typeof msg === 'string' ? msg : 'Something went wrong');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="pb-12">
      <PageHero
        title="Contact Us"
        subtitle="We'd love to hear from you! Send us your questions, feedback, or just say hello."
        icon={<Mail className="text-white" />}
      />

      <div className="mx-auto mt-10 flex max-w-5xl flex-col gap-8 px-4 sm:flex-row sm:px-6">
        <motion.div
          initial={{ opacity: 0, x: -30 }}
          animate={{ opacity: 1, x: 0 }}
          className="rounded-2xl bg-white p-6 shadow-lg sm:w-80"
        >
          <h3 className="font-display text-xl font-bold text-primary">Our Info</h3>
          <ul className="mt-5 space-y-4 text-muted">
            <li className="flex items-center gap-3">
              <MapPin className="shrink-0 text-primary" size={18} /> New Delhi
            </li>
            <li className="flex items-center gap-3">
              <Mail className="shrink-0 text-primary" size={18} /> harsharya072004@gmail.com
            </li>
            <li className="flex items-center gap-3">
              <Phone className="shrink-0 text-primary" size={18} /> +91 888 231 *****
            </li>
          </ul>
          <div className="mt-6">
            <a
              href="https://www.instagram.com/who_is_harshhh/"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-full bg-accent/10 px-4 py-2 font-semibold text-accent transition hover:bg-accent hover:text-white"
            >
              <Globe size={18} /> @who_is_harshhh
            </a>
          </div>
          <div className="mt-6 rounded-xl bg-[#f8f6fc] p-4 text-sm">
            <span className="flex items-center gap-1 font-bold text-accent">
              <Clock size={14} /> Support Hours
            </span>
            <p className="mt-1 text-muted">Mon - Fri: 8am - 8pm</p>
          </div>
        </motion.div>

        <motion.form
          initial={{ opacity: 0, x: 30 }}
          animate={{ opacity: 1, x: 0 }}
          onSubmit={handleSubmit}
          className="flex-1 space-y-4 rounded-2xl bg-white p-6 shadow-lg sm:p-8"
        >
          <div className="relative">
            <User className="absolute left-3 top-1/2 -translate-y-1/2 text-primary" size={18} />
            <input
              type="text"
              placeholder="Your Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="w-full rounded-xl border-2 border-[#e0c3fc] bg-[#f8f6fc] py-3 pl-11 pr-4 outline-none focus:border-primary"
            />
          </div>
          <div className="relative">
            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 text-primary" size={18} />
            <input
              type="email"
              placeholder="Your Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="w-full rounded-xl border-2 border-[#e0c3fc] bg-[#f8f6fc] py-3 pl-11 pr-4 outline-none focus:border-primary"
            />
          </div>
          <textarea
            placeholder="Your Message"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            required
            rows={5}
            className="w-full rounded-xl border-2 border-[#e0c3fc] bg-[#f8f6fc] px-4 py-3 outline-none focus:border-primary"
          />
          <button
            type="submit"
            disabled={submitting}
            className="flex w-full items-center justify-center gap-2 rounded-xl gradient-primary py-3.5 font-bold text-white shadow-lg transition hover:shadow-xl disabled:opacity-60"
          >
            <Send size={18} />
            {submitting ? 'Sending...' : 'Send Message'}
          </button>
        </motion.form>
      </div>
    </div>
  );
}
