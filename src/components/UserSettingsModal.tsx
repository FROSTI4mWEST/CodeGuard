import React, { useState } from 'react';
import { User, deleteUser, updateProfile } from 'firebase/auth';
import { doc, setDoc, deleteDoc, serverTimestamp } from 'firebase/firestore';
import { db, auth } from '../lib/firebase';
import { UserProfile } from '../types';
import { motion, AnimatePresence } from 'motion/react';
import { Github, Chrome } from 'lucide-react';

interface UserSettingsModalProps {
  user: User;
  profile: UserProfile | null;
  onClose: () => void;
  onLogout: () => void;
  onProfileUpdated?: (updated: UserProfile) => void;
}

export function UserSettingsModal({
  user,
  profile,
  onClose,
  onLogout,
  onProfileUpdated
}: UserSettingsModalProps) {
  const [displayName, setDisplayName] = useState(profile?.displayName || user.displayName || '');
  const [savingName, setSavingName] = useState(false);
  const [nameSavedSuccess, setNameSavedSuccess] = useState(false);
  const [saveNameError, setSaveNameError] = useState<string | null>(null);

  // Preferences toggles
  const [autoPatch, setAutoPatch] = useState(true);
  const [emailAlerts, setEmailAlerts] = useState(true);
  const [sastDepth, setSastDepth] = useState<'standard' | 'deep'>('deep');

  // Delete account workflow state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleteConfirmText, setDeleteConfirmText] = useState('');
  const [deletingAccount, setDeletingAccount] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const provider = user.providerData[0]?.providerId === 'google.com' ? 'Google OAuth' : 'GitHub OAuth';

  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = displayName.trim();
    if (!trimmed) return;
    setSavingName(true);
    setNameSavedSuccess(false);
    setSaveNameError(null);

    try {
      // 1. Update Firebase Auth user profile if currentUser exists
      if (auth.currentUser) {
        try {
          await updateProfile(auth.currentUser, { displayName: trimmed });
        } catch (aErr) {
          console.warn("Could not update Auth user profile:", aErr);
        }
      }

      // 2. Update/merge Firestore user document
      const userDocRef = doc(db, 'users', user.uid);
      await setDoc(userDocRef, {
        uid: user.uid,
        email: user.email || '',
        displayName: trimmed,
        updatedAt: serverTimestamp()
      }, { merge: true });

      // 3. Update parent component state
      if (onProfileUpdated) {
        onProfileUpdated({
          ...(profile || {
            uid: user.uid,
            email: user.email || '',
            displayName: trimmed,
            photoURL: user.photoURL || '',
            role: 'developer',
            createdAt: new Date().toISOString()
          }),
          displayName: trimmed
        });
      }

      setNameSavedSuccess(true);
      setTimeout(() => setNameSavedSuccess(false), 2500);
    } catch (err: any) {
      console.error("Failed to update profile:", err);
      setSaveNameError("Error updating display name: " + (err.message || String(err)));
    } finally {
      setSavingName(false);
    }
  };

  const handleDeleteAccount = async () => {
    if (deleteConfirmText.trim().toUpperCase() !== 'DELETE') return;
    setDeletingAccount(true);
    setDeleteError(null);

    try {
      // 1. Delete user profile document from Firestore
      const userDocRef = doc(db, 'users', user.uid);
      try {
        await deleteDoc(userDocRef);
      } catch (fErr) {
        console.warn("Error deleting Firestore profile document:", fErr);
      }

      // 2. Delete user account from Firebase Auth
      await deleteUser(user);

      // 3. Trigger sign out callback
      onLogout();
      onClose();
    } catch (err: any) {
      console.error("Account deletion failed:", err);
      if (err.code === 'auth/requires-recent-login') {
        setDeleteError('For security reasons, account deletion requires a fresh login. Please sign out, sign back in, and try deleting your account again.');
      } else {
        setDeleteError(err.message || 'Failed to delete account. Please try again.');
      }
    } finally {
      setDeletingAccount(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4 font-sans">
      {/* Backdrop */}
      <motion.div 
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="absolute inset-0 bg-slate-900/60 backdrop-blur-xs"
        onClick={onClose}
      />

      {/* Main Modal Box */}
      <motion.div
        initial={{ opacity: 0, scale: 0.95, y: 10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 10 }}
        className="relative bg-white border border-slate-200 rounded-2xl w-full max-w-xl max-h-[90vh] flex flex-col p-0 shadow-2xl overflow-hidden text-slate-800"
      >
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-100 bg-[#f8fafc] flex items-center justify-between">
          <div>
            <h3 className="font-bold text-slate-900 uppercase text-sm tracking-wider">
              USER ACCOUNT SETTINGS
            </h3>
          </div>
          <button 
            onClick={onClose}
            className="text-slate-400 hover:text-slate-700 transition-colors px-2 py-1 rounded-lg hover:bg-slate-100 cursor-pointer text-xs font-bold"
          >
            CLOSE
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-xs">
          {/* User Profile Info Card */}
          <div className="border border-slate-200 bg-[#f8fafc] rounded-2xl p-4 space-y-4">
            <div className="flex items-start gap-4">
              {profile?.photoURL ? (
                <img src={profile.photoURL} alt="" className="w-12 h-12 rounded-full border border-slate-200" />
              ) : (
                <div className="w-12 h-12 rounded-full bg-blue-50 border border-blue-200 flex items-center justify-center text-lg font-bold text-[#1976d2]">
                  {displayName.charAt(0) || 'U'}
                </div>
              )}
              <div className="space-y-1 flex-1">
                <div className="flex items-center justify-between">
                  <h4 className="font-bold text-slate-900 text-sm uppercase">{displayName || 'DEVELOPER'}</h4>
                  <span className="text-[10px] bg-white border border-slate-200 text-slate-700 px-2 py-0.5 rounded-full font-bold uppercase">
                    {profile?.role || 'DEVELOPER'}
                  </span>
                </div>
                <p className="text-slate-500 text-[11px] font-mono">{user.email || 'No email associated'}</p>
                <div className="pt-1 text-[11px] text-slate-500 font-medium flex items-center gap-1.5">
                  {user.providerData[0]?.providerId === 'google.com' ? (
                    <Chrome className="w-3.5 h-3.5 text-blue-600 inline" />
                  ) : (
                    <Github className="w-3.5 h-3.5 text-slate-800 inline" />
                  )}
                  <span>PROVIDER: {provider}</span>
                </div>
              </div>
            </div>

            {/* Edit Display Name Form */}
            <form onSubmit={handleSaveProfile} className="pt-3 border-t border-slate-200 space-y-2">
              <label className="block text-[11px] font-bold uppercase text-slate-700">
                UPDATE DISPLAY NAME
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="Enter display name..."
                  className="flex-1 bg-white border border-slate-200 rounded-xl px-3 py-1.5 text-xs text-slate-800 focus:outline-none focus:border-[#1976d2]"
                />
                <button
                  type="submit"
                  disabled={savingName}
                  className="github-btn-primary px-3 py-1.5 text-xs cursor-pointer font-semibold"
                >
                  {savingName ? 'SAVING...' : 'SAVE'}
                </button>
              </div>
              {nameSavedSuccess && (
                <p className="text-[11px] text-emerald-600 font-bold">
                  DISPLAY NAME UPDATED SUCCESSFULLY
                </p>
              )}
              {saveNameError && (
                <p className="text-[11px] text-red-600 font-bold">
                  {saveNameError}
                </p>
              )}
            </form>
          </div>

          {/* Account & Scan Preferences */}
          <div className="border border-slate-200 bg-white rounded-2xl p-4 space-y-3 shadow-xs">
            <h4 className="font-bold text-slate-900 text-xs uppercase border-b border-slate-100 pb-2">
              SECURITY & SCAN PREFERENCES
            </h4>

            <div className="space-y-2">
              <label className="flex items-center justify-between cursor-pointer p-2.5 hover:bg-slate-50 border border-slate-200 rounded-xl transition-colors">
                <div>
                  <div className="font-bold text-slate-800">AUTOMATED PR PATCH REMEDIATIONS</div>
                  <p className="text-[11px] text-slate-500">Allow CodeGuard to generate automatic pull request code fixes</p>
                </div>
                <input 
                  type="checkbox" 
                  checked={autoPatch} 
                  onChange={(e) => setAutoPatch(e.target.checked)}
                  className="accent-[#1976d2] w-4 h-4 cursor-pointer"
                />
              </label>

              <label className="flex items-center justify-between cursor-pointer p-2.5 hover:bg-slate-50 border border-slate-200 rounded-xl transition-colors">
                <div>
                  <div className="font-bold text-slate-800">SECURITY ALERT NOTIFICATIONS</div>
                  <p className="text-[11px] text-slate-500">Receive audit alerts for critical CWE vulnerability detections</p>
                </div>
                <input 
                  type="checkbox" 
                  checked={emailAlerts} 
                  onChange={(e) => setEmailAlerts(e.target.checked)}
                  className="accent-[#1976d2] w-4 h-4 cursor-pointer"
                />
              </label>

              <div className="flex items-center justify-between p-2.5 border border-slate-200 rounded-xl">
                <div>
                  <div className="font-bold text-slate-800">SAST AUDIT SCAN DEPTH</div>
                  <p className="text-[11px] text-slate-500">OWASP Top 10 rule enforcement scanning level</p>
                </div>
                <select 
                  value={sastDepth}
                  onChange={(e) => setSastDepth(e.target.value as any)}
                  className="bg-slate-50 border border-slate-200 rounded-lg text-slate-800 text-xs px-2.5 py-1 focus:outline-none focus:border-[#1976d2]"
                >
                  <option value="standard">STANDARD</option>
                  <option value="deep">DEEP (RECOMMENDED)</option>
                </select>
              </div>
            </div>
          </div>

          {/* Account Management & Logout */}
          <div className="border border-slate-200 bg-white rounded-2xl p-4 space-y-3 shadow-xs">
            <h4 className="font-bold text-slate-900 text-xs uppercase border-b border-slate-100 pb-2">
              SESSION MANAGEMENT
            </h4>

            <div className="flex items-center justify-between">
              <div>
                <div className="font-bold text-slate-800">SIGN OUT OF SESSION</div>
                <p className="text-[11px] text-slate-500">Disconnect session credentials from this browser</p>
              </div>
              <button
                onClick={() => { onLogout(); onClose(); }}
                className="github-btn-secondary px-3.5 py-1.5 text-xs font-semibold cursor-pointer"
              >
                LOGOUT
              </button>
            </div>
          </div>

          {/* Danger Zone: Delete Account */}
          <div className="border border-red-200 bg-red-50/50 rounded-2xl p-4 space-y-3">
            <h4 className="font-bold text-red-700 text-xs uppercase border-b border-red-200 pb-2">
              DANGER ZONE: ACCOUNT DELETION
            </h4>

            {!showDeleteConfirm ? (
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-bold text-red-700">PERMANENTLY DELETE ACCOUNT</div>
                  <p className="text-[11px] text-red-600/80">Erase profile data, security rules, and disconnect repositories</p>
                </div>
                <button
                  onClick={() => setShowDeleteConfirm(true)}
                  className="bg-red-600 hover:bg-red-700 text-white font-bold px-3.5 py-1.5 rounded-lg text-xs transition-colors cursor-pointer"
                >
                  DELETE ACCOUNT
                </button>
              </div>
            ) : (
              <div className="space-y-3 pt-1">
                <div className="text-red-700 text-xs font-bold">
                  <span>THIS ACTION CANNOT BE UNDONE!</span>
                </div>
                <p className="text-[11px] text-red-700">
                  Type <span className="font-bold underline text-red-900">DELETE</span> in the box below to confirm permanent account deletion.
                </p>

                <input
                  type="text"
                  value={deleteConfirmText}
                  onChange={(e) => setDeleteConfirmText(e.target.value)}
                  placeholder="Type DELETE..."
                  className="w-full bg-white border border-red-300 rounded-xl px-3 py-2 text-xs text-red-700 focus:outline-none focus:border-red-500"
                  autoFocus
                />

                {deleteError && (
                  <p className="text-[11px] text-red-700 font-bold leading-relaxed border border-red-200 bg-white rounded-xl p-2">
                    {deleteError}
                  </p>
                )}

                <div className="flex gap-2 justify-end pt-2">
                  <button
                    onClick={() => { setShowDeleteConfirm(false); setDeleteConfirmText(''); setDeleteError(null); }}
                    className="github-btn-secondary px-3 py-1.5 text-xs cursor-pointer font-semibold"
                  >
                    CANCEL
                  </button>
                  <button
                    onClick={handleDeleteAccount}
                    disabled={deleteConfirmText.trim().toUpperCase() !== 'DELETE' || deletingAccount}
                    className="bg-red-600 text-white px-4 py-1.5 text-xs font-bold rounded-lg disabled:opacity-40 disabled:cursor-not-allowed hover:bg-red-700 transition-colors cursor-pointer"
                  >
                    {deletingAccount ? 'DELETING ACCOUNT...' : 'CONFIRM ERASURE'}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3 border-t border-slate-100 bg-[#f8fafc] flex justify-end">
          <button
            onClick={onClose}
            className="github-btn-secondary px-4 py-1.5 text-xs cursor-pointer font-semibold"
          >
            CLOSE
          </button>
        </div>
      </motion.div>
    </div>
  );
}
