import * as React from "react";
import { useMutation } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/useToast";
import { apiPost, PasskeyAdminError } from "@/lib/api";

const schema = z
  .object({
    oldPassword: z.string().min(1, "현재 비밀번호를 입력하세요"),
    newPassword: z.string().min(12, "12자 이상").max(128),
    newPasswordConfirm: z.string(),
  })
  .refine((d) => d.newPassword === d.newPasswordConfirm, {
    message: "새 비밀번호가 일치하지 않습니다",
    path: ["newPasswordConfirm"],
  });

type Form = z.infer<typeof schema>;

export function ChangeMyPasswordDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { toast } = useToast();
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<Form>({ resolver: zodResolver(schema) });

  React.useEffect(() => {
    if (!open) reset();
  }, [open, reset]);

  const change = useMutation({
    mutationFn: (req: { oldPassword: string; newPassword: string }) =>
      apiPost<void>("/api/v1/admin/me/password", req),
    onSuccess: () => {
      toast({ variant: "success", title: "비밀번호가 변경되었습니다." });
      onOpenChange(false);
    },
    onError: (e: PasskeyAdminError) =>
      toast({ variant: "destructive", title: e.code, description: e.message }),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>내 비밀번호 변경</DialogTitle>
          <DialogDescription>
            새 비밀번호는 12자 이상이어야 합니다.
          </DialogDescription>
        </DialogHeader>
        <form
          id="change-pwd-form"
          onSubmit={handleSubmit((d) =>
            change.mutate({ oldPassword: d.oldPassword, newPassword: d.newPassword }),
          )}
          className="space-y-3"
        >
          <div className="space-y-1.5">
            <Label htmlFor="oldPassword">현재 비밀번호</Label>
            <Input id="oldPassword" type="password" autoFocus {...register("oldPassword")} />
            {errors.oldPassword && (
              <p className="text-xs text-destructive">{errors.oldPassword.message}</p>
            )}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="newPassword">새 비밀번호</Label>
            <Input id="newPassword" type="password" {...register("newPassword")} />
            {errors.newPassword && (
              <p className="text-xs text-destructive">{errors.newPassword.message}</p>
            )}
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="newPasswordConfirm">새 비밀번호 확인</Label>
            <Input
              id="newPasswordConfirm"
              type="password"
              {...register("newPasswordConfirm")}
            />
            {errors.newPasswordConfirm && (
              <p className="text-xs text-destructive">
                {errors.newPasswordConfirm.message}
              </p>
            )}
          </div>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            취소
          </Button>
          <Button type="submit" form="change-pwd-form" disabled={isSubmitting || change.isPending}>
            {change.isPending ? "변경 중…" : "변경"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
