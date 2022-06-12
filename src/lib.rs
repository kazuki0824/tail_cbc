mod decrypt;
mod encrypt;
mod unaligned_bytes;
mod unaligned_bytes_mut;

pub use cipher;
pub use decrypt::Decryptor;
pub use encrypt::Encryptor;

use crate::unaligned_bytes_mut::{UnalignedBytesDecryptMut, UnalignedBytesEncryptMut};
use cipher::generic_array::{ArrayLength, GenericArray};
use cipher::inout::InOutBuf;
use cipher::{
    Block, BlockCipher, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut,
    BlockSizeUser
};

#[inline(always)]
fn xor<N: ArrayLength<u8>>(out: &mut GenericArray<u8, N>, buf: &GenericArray<u8, N>) {
    for (a, b) in out.iter_mut().zip(buf) {
        *a ^= *b;
    }
}

/// If unaligned tail procesing failed, this struct should be returned.
#[derive(Debug)]
pub struct TailError;

impl<C: BlockCipher + BlockDecryptMut + BlockEncrypt + BlockSizeUser> UnalignedBytesDecryptMut
    for Decryptor<C>
{
    fn proc_tail(
        &self,
        blocks: &mut InOutBuf<'_, '_, Block<Self>>,
        tail: &mut InOutBuf<'_, '_, u8>,
    ) -> Result<(), TailError> {
        match blocks.get_in().last() {
            Some(last) => {
                let mut last: Block<C> = last.clone();
                self.cipher.encrypt_block(&mut last);
                tail.xor_in2out(&last[0..tail.len()]);
                Ok(())
            }
            None => Err(TailError {}),
        }
    }
}
impl<C: BlockCipher + BlockEncryptMut + BlockDecrypt + BlockSizeUser> UnalignedBytesEncryptMut
    for Encryptor<C>
{
    fn proc_tail(
        &self,
        blocks: &mut InOutBuf<'_, '_, Block<Self>>,
        tail: &mut InOutBuf<'_, '_, u8>,
    ) -> Result<(), TailError> {
        match blocks.get_in().last() {
            Some(last) => {
                let mut last: Block<C> = last.clone();
                self.cipher.decrypt_block(&mut last);
                tail.xor_in2out(&last[0..tail.len()]);
                Ok(())
            }
            None => Err(TailError {}),
        }
    }
}
