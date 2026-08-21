import { db } from './firebase';
import { collection, addDoc, serverTimestamp } from 'firebase/firestore';
import { type AuditLog } from '../types';

export async function logAuditAction(userId: string, email: string, action: string, details: string, resourceType?: string, resourceId?: string) {
  try {
    await addDoc(collection(db, 'auditLogs'), {
      userId,
      userEmail: email,
      action,
      details,
      resourceType,
      resourceId,
      timestamp: serverTimestamp(),
    });
  } catch (error) {
    console.error('Failed to log audit action:', error);
  }
}
