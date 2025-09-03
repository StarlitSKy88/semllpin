import React from 'react';
import { Modal } from 'antd';
import { useUIStore } from '../../stores/uiStore';

interface ProfileModalProps {
  modalId: string;
}

const ProfileModal: React.FC<ProfileModalProps> = ({ modalId }) => {
  const { closeModal } = useUIStore();

  return (
    <Modal
      title="个人资料"
      open={true}
      onCancel={() => closeModal(modalId)}
      footer={null}
    >
      <p>个人资料功能开发中...</p>
    </Modal>
  );
};

export default ProfileModal;