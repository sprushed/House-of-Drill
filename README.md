## House of Drill

##### Yet another FSOP technique


### Breakdown
The house of Drill offers an easy and convenient way to get an arbitrary write using [FSOP](https://ctf-wiki.mahaloz.re/pwn/linux/io_file/fsop/).

### About _IO_wide_data structure  
There's a field in _IO_FILE structure that's being undeservedly ignored: pointer to struct _IO_wide_data. 
    
    struct _IO_FILE {
            ...
            struct _IO_wide_data *_wide_data;
            ...
        };

This is a structure that looks similar to a regular _IO_FILE struct, but is used for wide character streams.

    struct _IO_wide_data
    {
      wchar_t *_IO_read_ptr;	/* Current read pointer */
      wchar_t *_IO_read_end;	/* End of get area. */
      wchar_t *_IO_read_base;	/* Start of putback+get area. */
      wchar_t *_IO_write_base;	/* Start of put area. */
      wchar_t *_IO_write_ptr;	/* Current put pointer. */
      wchar_t *_IO_write_end;	/* End of put area. */
      wchar_t *_IO_buf_base;	/* Start of reserve area. */
      wchar_t *_IO_buf_end;		/* End of reserve area. */
      /* The following fields are used to support backing up and undo. */
      wchar_t *_IO_save_base;	/* Pointer to start of non-current get area. */
      wchar_t *_IO_backup_base;	/* Pointer to first valid character of
    				   backup area */
      wchar_t *_IO_save_end;	/* Pointer to end of non-current get area. */
      __mbstate_t _IO_state;
      __mbstate_t _IO_last_state;
      struct _IO_codecvt _codecvt;
      wchar_t _shortbuf[1];
      const struct _IO_jump_t *_wide_vtable;
    };


But we are not really interested in this particular structure but in the cornerstone of most FSOP exploitaion techniques: the vtable also known as  _wida_data vtable or as it's called in GLIBC source code:
    
    const struct _IO_jump_t _IO_wstrn_jumps = {
        __dummy = 0x0,
        __dummy2 = 0x0,
        __finish = 0x7ffff7c84c20 <_IO_wstr_finish>,
        __overflow = 0x7ffff7c82f80 <_IO_wstrn_overflow>,
        __underflow = 0x7ffff7c84750 <_IO_wstr_underflow>,
        __uflow = 0x7ffff7c838c0 <__GI__IO_wdefault_uflow>,
        __pbackfail = 0x7ffff7c84c00 <_IO_wstr_pbackfail>,
        __xsputn = 0x7ffff7c839b0 <__GI__IO_wdefault_xsputn>,
        __xsgetn = 0x7ffff7c840b0 <__GI__IO_wdefault_xsgetn>,
        __seekoff = 0x7ffff7c84d70 <_IO_wstr_seekoff>,
        __seekpos = 0x7ffff7c8e530 <_IO_default_seekpos>,
        __setbuf = 0x7ffff7c8e430 <_IO_default_setbuf>,
        __sync = 0x7ffff7c8e7a0 <_IO_default_sync>,
        __doallocate = 0x7ffff7c83ca0 <__GI__IO_wdefault_doallocate>,
        __read = 0x7ffff7c8f480 <_IO_default_read>,
        __write = 0x7ffff7c8f490 <_IO_default_write>,
        __seek = 0x7ffff7c8f460 <_IO_default_seek>,
        __close = 0x7ffff7c8e7a0 <_IO_default_sync>,
        __stat = 0x7ffff7c8f470 <_IO_default_stat>,
        __showmanyc = 0x7ffff7c8f4a0 <_IO_default_showmanyc>,
        __imbue = 0x7ffff7c8f4b0 <_IO_default_imbue>
    };

In most of the wstrn functinons the _wide_data field of a _IO_FILE structure get dereferenced and interacted with, which gives us an opportunity to point it somewhere in the binary to gain a primitive of an arbitrary write

### Exploitation  
The House of Drill starts with the assumption that a primitive that allows to create a custom _IO_FILE structure and link it in _IO_list_all *OR* overwrite an existing one with slight margin exists. If all the conditions are met, we shall begin the explanation of this technique. This attack could be triggered in following ways:

 - Return from main() functinon
 - When libc executes abort from a process
 - When executing the exit function

 As you can see the beauty of this attack is that it can be triggered almost always, because all of this cases trigger _IO_flush_all_lock. Which in turn [triggers the __overflow field](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/genops.c#L706) in all _IO_FILE structures's jump tables.  

 In _IO_wstrn_jumps __overflow field corresponds to the [_IO_wstrn_overflow](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/vswprintf.c#L34) function which

 - Casts our struct to the _IO_wstrnfile type

        _IO_wstrnfile *snf = (_IO_wstrnfile *) fp;

 - Does a simple check 

        #snf -> overflow_buf is at 0xf0 from out FILE *
        if (fp->_wide_data->_IO_buf_base != snf->overflow_buf)

 - Performes the desired write 

        fp->_wide_data->_IO_write_base = snf->overflow_buf;
        fp->_wide_data->_IO_read_base = snf->overflow_buf;
        fp->_wide_data->_IO_read_ptr = snf->overflow_buf;

        #this write executes independently of the check
        fp->_wide_data->_IO_write_ptr = snf->overflow_buf;
        fp->_wide_data->_IO_write_end = snf->overflow_buf;


So basically our plain is quite simple. If we point the _wide_data of our _IO_FILE struct anywhere near the write location we can overwrite it with snf -> overflow_buf value

If we break it down into specific steps, we get something like following

 - Create fake FILE structure and link it in _IO_list_all or overwrite the _wide_data and vtable of an existing one

 - Point vtable of the FILE structure to _IO_wstrn_jumps

 - Point _wide_data of the FILE structure at offset from 0 to 0x28 of location desired for writing

 - Put the value you want to write at 0xf0 from beginning of the FILE struct

 - Trigger _IO_flush_all_lock using any method that was listed at the beginning

 That's about it with the house of Drill. Hope this technique will help you in solving your next FSOP task.
